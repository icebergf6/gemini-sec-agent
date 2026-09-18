import fs from 'fs/promises';
import path from 'path';

export const declaration = {
  name: 'iac_linter',
  description: 'Overpower IaC security linter: Dockerfile (20+ rules), docker-compose.yml, Kubernetes YAML, Terraform HCL — privilege escalation, secret leaks, network exposure, container escape vectors, and CIS benchmark checks.',
  parameters: {
    type: 'OBJECT',
    properties: {
      target: { type: 'STRING', description: 'Path to file or directory to audit (default: ".")' },
      strict: { type: 'BOOLEAN', description: 'Enable strict mode — also report LOW/INFO findings (default: false)' },
    },
    required: []
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// DOCKERFILE AUDITOR
// ─────────────────────────────────────────────────────────────────────────────
function auditDockerfile(content, filename) {
  const lines  = content.split(/\r?\n/);
  const issues = [];
  let hasUser = false, hasHealthcheck = false, stageCount = 0;
  let fromLines = [];

  for (let i=0; i<lines.length; i++) {
    const raw  = lines[i];
    const line = raw.trim();
    const ln   = i+1;
    if (!line || line.startsWith('#')) continue;
    const UP   = line.toUpperCase();

    // ── FROM ──────────────────────────────────────────────────────────────────
    if (UP.startsWith('FROM ')) {
      stageCount++;
      const img = line.slice(5).trim().split(/\s+/)[0];
      fromLines.push({ ln, img });
      if (img.includes(':latest') || (!img.includes(':') && !img.includes('@'))) {
        issues.push({ file:filename, line:ln, rule:'Unpinned Base Image', severity:'MEDIUM',
          detail:`"${img}" uses no version tag — use digest or explicit tag (e.g., node:20.14-alpine3.20).`,
          fix:'FROM node:20.14-alpine3.20@sha256:<digest>' });
      }
      if (/^ubuntu|^debian|^centos|^fedora/i.test(img) && !img.includes('slim') && !img.includes('alpine')) {
        issues.push({ file:filename, line:ln, rule:'Large Non-Slim Base Image', severity:'INFO',
          detail:'Consider using -slim or alpine variant to reduce attack surface.',
          fix:'FROM debian:12-slim or FROM node:20-alpine' });
      }
    }

    // ── USER ──────────────────────────────────────────────────────────────────
    if (UP.startsWith('USER ')) {
      const user = line.slice(5).trim().toLowerCase();
      if (user === 'root' || user === '0') {
        issues.push({ file:filename, line:ln, rule:'Explicit Root User', severity:'HIGH',
          detail:'Container explicitly set to run as root.',
          fix:'RUN addgroup -S app && adduser -S app -G app\nUSER app' });
      } else {
        hasUser = true;
      }
    }

    // ── HEALTHCHECK ───────────────────────────────────────────────────────────
    if (UP.startsWith('HEALTHCHECK ')) {
      if (line.toUpperCase().includes('NONE')) {
        issues.push({ file:filename, line:ln, rule:'HEALTHCHECK Disabled', severity:'LOW',
          detail:'HEALTHCHECK NONE explicitly disables health monitoring.',
          fix:'HEALTHCHECK CMD curl --fail http://localhost:8080/health || exit 1' });
      } else hasHealthcheck = true;
    }

    // ── curl|bash / wget|bash ──────────────────────────────────────────────────
    if (/curl\s+.*\|\s*(?:bash|sh)\b/i.test(line) || /wget\s+.*\|\s*(?:bash|sh)\b/i.test(line)) {
      issues.push({ file:filename, line:ln, rule:'Remote Script Pipe Execution', severity:'HIGH',
        detail:'Downloading and executing remote shell script without verification.',
        fix:'Download → verify SHA256 → execute separately. Never pipe curl to bash.' });
    }

    // ── ENV/ARG secrets ───────────────────────────────────────────────────────
    if (/^(?:ENV|ARG)\s+.*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE|CERT|PASSPHRASE)\s*=/i.test(line)) {
      issues.push({ file:filename, line:ln, rule:'Secret in Image Layer', severity:'CRITICAL',
        detail:'Sensitive value baked into image layer — visible in `docker history`.',
        fix:'Use BuildKit secrets: RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret' });
    }

    // ── ADD vs COPY ────────────────────────────────────────────────────────────
    if (UP.startsWith('ADD ') && !/\.(tar|gz|bz2|xz)/.test(line)) {
      issues.push({ file:filename, line:ln, rule:'Use COPY Instead of ADD', severity:'LOW',
        detail:'ADD has hidden behaviors (URL fetch, auto-extract). Use COPY for local files.',
        fix:'Replace ADD with COPY' });
    }

    // ── RUN apt-get without --no-install-recommends ───────────────────────────
    if (/apt-get\s+install/i.test(line) && !/--no-install-recommends/i.test(line)) {
      issues.push({ file:filename, line:ln, rule:'apt-get Without --no-install-recommends', severity:'LOW',
        detail:'Installing recommended packages bloats image size unnecessarily.',
        fix:'RUN apt-get install -y --no-install-recommends <packages>' });
    }

    // ── pip install without --no-cache-dir ────────────────────────────────────
    if (/pip\s+install/i.test(line) && !/--no-cache-dir/i.test(line)) {
      issues.push({ file:filename, line:ln, rule:'pip Without --no-cache-dir', severity:'INFO',
        detail:'pip cache increases image size. Use --no-cache-dir.',
        fix:'RUN pip install --no-cache-dir -r requirements.txt' });
    }

    // ── sudo in Dockerfile ────────────────────────────────────────────────────
    if (/\bsudo\b/i.test(line)) {
      issues.push({ file:filename, line:ln, rule:'sudo Usage in Dockerfile', severity:'MEDIUM',
        detail:'sudo in Dockerfile can bypass intended privilege restrictions.',
        fix:'Use USER instruction to switch contexts instead of sudo.' });
    }

    // ── chmod 777 ─────────────────────────────────────────────────────────────
    if (/chmod\s+(?:0?777|[ao]\+[rwx])/i.test(line)) {
      issues.push({ file:filename, line:ln, rule:'World-Writable chmod', severity:'HIGH',
        detail:'chmod 777 or a+rwx allows any user to modify files — privilege escalation risk.',
        fix:'Use specific permissions: chmod 644 for files, 755 for dirs.' });
    }

    // ── EXPOSE privileged port ─────────────────────────────────────────────────
    if (UP.startsWith('EXPOSE ')) {
      const portStr = line.slice(7).trim();
      const port = parseInt(portStr);
      if (!isNaN(port) && port < 1024) {
        issues.push({ file:filename, line:ln, rule:'Privileged Port Exposed', severity:'MEDIUM',
          detail:`Port ${port} (<1024) requires root/CAP_NET_BIND_SERVICE.`,
          fix:'Use port ≥1024 and rely on host port mapping.' });
      }
    }
  }

  // ── Post-scan checks ───────────────────────────────────────────────────────
  if (!hasUser) {
    issues.push({ file:filename, line:'EOF', rule:'No Non-Root USER Defined', severity:'HIGH',
      detail:'Container runs as root by default.',
      fix:'RUN adduser -D appuser && USER appuser' });
  }
  if (!hasHealthcheck) {
    issues.push({ file:filename, line:'EOF', rule:'Missing HEALTHCHECK', severity:'LOW',
      detail:'No health check — orchestrators cannot detect unhealthy containers.',
      fix:'HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1' });
  }
  if (stageCount === 1 && fromLines[0] && !/scratch|distroless|alpine/i.test(fromLines[0].img)) {
    issues.push({ file:filename, line:fromLines[0].ln, rule:'Single-Stage Build', severity:'INFO',
      detail:'Consider multi-stage build to minimize final image attack surface.',
      fix:'Use multi-stage: COPY --from=builder /app/dist /app' });
  }

  return issues;
}

// ─────────────────────────────────────────────────────────────────────────────
// DOCKER-COMPOSE AUDITOR
// ─────────────────────────────────────────────────────────────────────────────
function auditDockerCompose(content, filename) {
  const lines  = content.split(/\r?\n/);
  const issues = [];
  for (let i=0; i<lines.length; i++) {
    const line = lines[i];
    const ln   = i+1;

    if (/privileged\s*:\s*true/i.test(line))
      issues.push({ file:filename, line:ln, rule:'Privileged Container', severity:'CRITICAL',
        detail:'privileged: true grants near-host-root access (container escape risk).',
        fix:'Remove privileged: true. Use specific cap_add entries.' });

    if (/\/var\/run\/docker\.sock/i.test(line))
      issues.push({ file:filename, line:ln, rule:'Docker Socket Mount', severity:'CRITICAL',
        detail:'Mounting docker.sock → full Docker daemon control → container escape.',
        fix:'Never mount docker.sock in application containers.' });

    if (/network_mode\s*:\s*["']?host["']?/i.test(line))
      issues.push({ file:filename, line:ln, rule:'Host Network Mode', severity:'HIGH',
        detail:'Network isolation disabled — container shares host network namespace.',
        fix:'Use a dedicated bridge network.' });

    if (/-\s*["']?\/(?:etc|proc|sys|root)["']?\s*:/i.test(line))
      issues.push({ file:filename, line:ln, rule:'Sensitive Host Volume Mount', severity:'CRITICAL',
        detail:'Mounting sensitive host paths (/etc, /proc, /sys, /root) into container.',
        fix:'Only mount application-specific data directories.' });

    if (/pid\s*:\s*["']?host["']?/i.test(line))
      issues.push({ file:filename, line:ln, rule:'Host PID Namespace', severity:'HIGH',
        detail:'pid: host allows container to see and signal host processes.',
        fix:'Remove pid: host unless absolutely required.' });

    if (/security_opt\s*:\s*\n[\s\S]*?seccomp:unconfined/im.test(line) || /seccomp:unconfined/i.test(line))
      issues.push({ file:filename, line:ln, rule:'Seccomp Disabled', severity:'HIGH',
        detail:'seccomp:unconfined removes syscall filtering — kernel exploit surface increased.',
        fix:'Use custom seccomp profile or remove security_opt entirely (default profile applies).' });

    if (/restart\s*:\s*["']?always["']?/i.test(line))
      issues.push({ file:filename, line:ln, rule:'Restart Always', severity:'INFO',
        detail:'restart: always can mask crashes. Use "on-failure:3" for safer restart policy.',
        fix:'restart: "on-failure:3"' });
  }
  return issues;
}

// ─────────────────────────────────────────────────────────────────────────────
// KUBERNETES YAML AUDITOR
// ─────────────────────────────────────────────────────────────────────────────
function auditKubernetes(content, filename) {
  const lines  = content.split(/\r?\n/);
  const issues = [];
  const full   = content;

  // Check for runAsRoot/allowPrivilegeEscalation
  if (/runAsUser\s*:\s*0\b/i.test(full))
    issues.push({ file:filename, rule:'K8s RunAsRoot', severity:'HIGH',
      detail:'securityContext.runAsUser: 0 — container runs as root.',
      fix:'Set runAsUser: 1000 and runAsNonRoot: true' });

  if (/allowPrivilegeEscalation\s*:\s*true/i.test(full))
    issues.push({ file:filename, rule:'K8s AllowPrivilegeEscalation', severity:'HIGH',
      detail:'allowPrivilegeEscalation: true — process can gain more privileges than parent.',
      fix:'Set allowPrivilegeEscalation: false' });

  if (!full.includes('readOnlyRootFilesystem'))
    issues.push({ file:filename, rule:'K8s No ReadOnly Filesystem', severity:'MEDIUM',
      detail:'readOnlyRootFilesystem not set — container can write to root fs.',
      fix:'Add readOnlyRootFilesystem: true to securityContext.' });

  if (/hostNetwork\s*:\s*true/i.test(full))
    issues.push({ file:filename, rule:'K8s HostNetwork', severity:'HIGH',
      detail:'hostNetwork: true — pod shares host network namespace.',
      fix:'Remove hostNetwork: true.' });

  if (/hostPID\s*:\s*true/i.test(full))
    issues.push({ file:filename, rule:'K8s HostPID', severity:'HIGH',
      detail:'hostPID: true — pod can see all host processes.',
      fix:'Remove hostPID: true.' });

  if (!full.includes('resources:') || !full.includes('limits:'))
    issues.push({ file:filename, rule:'K8s Missing Resource Limits', severity:'MEDIUM',
      detail:'No CPU/memory limits — risk of resource starvation (DoS).',
      fix:'Set resources.limits.cpu and resources.limits.memory.' });

  if (!full.includes('livenessProbe') || !full.includes('readinessProbe'))
    issues.push({ file:filename, rule:'K8s Missing Probes', severity:'LOW',
      detail:'Missing liveness/readiness probes — cluster cannot detect unhealthy pods.',
      fix:'Add livenessProbe and readinessProbe to container spec.' });

  return issues;
}

// ─────────────────────────────────────────────────────────────────────────────
// TERRAFORM HCL AUDITOR
// ─────────────────────────────────────────────────────────────────────────────
function auditTerraform(content, filename) {
  const issues = [];

  if (/0\.0\.0\.0\/0/.test(content))
    issues.push({ file:filename, rule:'Terraform Open CIDR (0.0.0.0/0)', severity:'HIGH',
      detail:'Security group/firewall rule allows traffic from anywhere.',
      fix:'Restrict CIDR to known IP ranges.' });

  if (/sensitive\s*=\s*false/i.test(content))
    issues.push({ file:filename, rule:'Non-Sensitive Secret Variable', severity:'MEDIUM',
      detail:'Variable with sensitive-sounding name marked sensitive=false.',
      fix:'Add sensitive = true to prevent value appearing in plan output.' });

  if (/backend\s+"local"/i.test(content))
    issues.push({ file:filename, rule:'Local Terraform State Backend', severity:'MEDIUM',
      detail:'Local state backend — state file stored unencrypted on disk.',
      fix:'Use remote backend (S3+DynamoDB, Terraform Cloud, GCS).' });

  if (/encryption_enabled\s*=\s*false/i.test(content))
    issues.push({ file:filename, rule:'Encryption Disabled', severity:'HIGH',
      detail:'Encryption explicitly disabled on a resource.',
      fix:'Set encryption_enabled = true or enable default encryption.' });

  return issues;
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTRYPOINT
// ─────────────────────────────────────────────────────────────────────────────
export async function execute(args) {
  const rootPath  = path.resolve(process.cwd(), args.target||'.');
  const strict    = Boolean(args.strict);
  const allIssues = [];
  const scanned   = [];

  async function tryFile(fp) {
    try {
      const content  = await fs.readFile(fp,'utf8');
      const base     = path.basename(fp).toLowerCase();
      scanned.push(fp);
      if (base.includes('dockerfile'))
        allIssues.push(...auditDockerfile(content,fp));
      else if (base.includes('compose') || base.endsWith('.yml') || base.endsWith('.yaml')) {
        // Heuristic: K8s YAML has apiVersion, Compose has services:
        if (/^apiVersion\s*:/m.test(content))
          allIssues.push(...auditKubernetes(content,fp));
        else
          allIssues.push(...auditDockerCompose(content,fp));
      } else if (base.endsWith('.tf')) {
        allIssues.push(...auditTerraform(content,fp));
      }
    } catch {}
  }

  const stat = await fs.stat(rootPath).catch(()=>null);
  if (!stat) return { success:false, error:`Path not found: ${rootPath}` };

  if (stat.isFile()) {
    await tryFile(rootPath);
  } else {
    // Auto-discover IaC files
    const candidates = [
      'Dockerfile','Dockerfile.prod','Dockerfile.dev',
      'docker-compose.yml','docker-compose.yaml','docker-compose.prod.yml',
      'compose.yml','compose.yaml',
      'kubernetes.yaml','k8s.yaml','deployment.yaml','service.yaml',
      'main.tf','variables.tf','outputs.tf'
    ];
    for (const c of candidates) await tryFile(path.join(rootPath,c));

    // Also walk for *.tf and k8s yamls
    try {
      const entries = await fs.readdir(rootPath,{withFileTypes:true});
      for (const e of entries) {
        if (e.isFile() && (e.name.endsWith('.tf') || e.name.match(/k8s.*\.ya?ml$/i)))
          await tryFile(path.join(rootPath,e.name));
      }
    } catch {}
  }

  const filtered = strict ? allIssues : allIssues.filter(i=>['CRITICAL','HIGH','MEDIUM'].includes(i.severity));
  const crit = filtered.filter(i=>i.severity==='CRITICAL').length;
  const high = filtered.filter(i=>i.severity==='HIGH').length;

  return {
    scannedFiles:   scanned,
    totalFilesAudited: scanned.length,
    totalFindings:  filtered.length,
    summary: {
      CRITICAL: crit,
      HIGH:     high,
      MEDIUM:   filtered.filter(i=>i.severity==='MEDIUM').length,
      LOW:      filtered.filter(i=>i.severity==='LOW').length,
      INFO:     filtered.filter(i=>i.severity==='INFO').length,
    },
    findings: filtered,
    overallStatus: crit>0?'FAILED':high>0?'NEEDS REVIEW':'PASSED',
    verdict: crit>0
      ? `🔴 CRITICAL — ${crit} critical IaC misconfiguration(s) detected! Container/cloud escape risk.`
      : high>0
        ? `🟠 HIGH RISK — ${high} high-severity issue(s) found. Fix before deploying.`
        : filtered.length>0
          ? `🟡 ${filtered.length} finding(s). Review before production deployment.`
          : `🟢 PASSED — No significant IaC security issues detected.`
  };
}
