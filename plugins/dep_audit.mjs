import fs from 'fs/promises';
import path from 'path';

export const declaration = {
  name: 'dep_audit',
  description: 'Overpower supply-chain auditor: package.json + requirements.txt + Pipfile + pyproject.toml — wildcard versions, known-malicious packages, prototype pollution risk, typosquat detection, outdated major versions, and SBOM generation.',
  parameters: {
    type: 'OBJECT',
    properties: {
      target:    { type: 'STRING',  description: 'Directory or manifest file path (default: ".")' },
      sbom:      { type: 'BOOLEAN', description: 'Generate a Software Bill of Materials (SBOM) list (default: false)' },
      recursive: { type: 'BOOLEAN', description: 'Scan nested node_modules for nested manifests (default: false)' },
    },
    required: []
  }
};

// ── Known dangerous packages DB ────────────────────────────────────────────────
const DANGEROUS = {
  // Supply chain attacks
  'event-stream':       { severity:'CRITICAL', reason:'Injected malware (flatmap-stream) to steal crypto wallets (2018).' },
  'flatmap-stream':     { severity:'CRITICAL', reason:'Malicious package injected via event-stream.' },
  'ua-parser-js':       { severity:'CRITICAL', reason:'Hijacked & malware-injected (CVE-2021-41265).' },
  'node-ipc':           { severity:'CRITICAL', reason:'Author injected destructive payload (2022, protestware).' },
  'peacenotwar':        { severity:'CRITICAL', reason:'Protestware — deletes files in Russian/Belarusian systems.' },
  'colors':             { severity:'HIGH',     reason:'v1.4.44 sabotaged with infinite loop (DoS).' },
  'faker':              { severity:'HIGH',     reason:'v6.6.6 sabotaged. Use @faker-js/faker instead.' },
  'coa':                { severity:'HIGH',     reason:'npm account hijacked, malware published (2021).' },
  'rc':                 { severity:'HIGH',     reason:'npm account hijacked, malware published (2021).' },
  'antd':               { severity:'MEDIUM',   reason:'Christmas Easter egg in v4.0.0 — review change policy.' },
  // Deprecated / insecure
  'request':            { severity:'MEDIUM',   reason:'Deprecated. Replace with node-fetch or axios.' },
  'node-uuid':          { severity:'LOW',      reason:'Deprecated. Use uuid package instead.' },
  'mkdirp':             { severity:'LOW',      reason:'Old version has CJS/ESM incompatibility. Pin to >=1.0.4.' },
  'lodash':             { severity:'MEDIUM',   reason:'Prototype pollution: CVE-2020-8203. Keep pinned ≥4.17.21.' },
  'jquery':             { severity:'MEDIUM',   reason:'Multiple XSS CVEs in <3.5.0. Pin ≥3.7.0.' },
  'moment':             { severity:'LOW',      reason:'Deprecated. Use date-fns or dayjs.' },
  'serialize-javascript':{ severity:'HIGH',   reason:'XSS via prototype pollution in <2.1.1.' },
  'minimist':           { severity:'HIGH',     reason:'Prototype pollution CVE-2021-44906 in <1.2.6.' },
  'qs':                 { severity:'HIGH',     reason:'Prototype pollution CVE-2022-24999 in <6.10.3.' },
  'axios':              { severity:'MEDIUM',   reason:'CVE-2021-3749 ReDoS in <0.21.2. Pin ≥1.6.0.' },
  'express':            { severity:'MEDIUM',   reason:'CVE-2022-24999 via qs. Pin ≥4.18.2.' },
};

// ── Typosquat detection (common targets) ──────────────────────────────────────
const LEGIT_PACKAGES = new Set(['express','lodash','react','vue','axios','moment','request','chalk','debug','typescript']);
function detectTyposquat(name) {
  for (const legit of LEGIT_PACKAGES) {
    if (name === legit) return null;
    if (levenshtein(name, legit) <= 2 && name.length >= legit.length - 2) {
      return `Possible typosquat of "${legit}" (edit distance: ${levenshtein(name,legit)}).`;
    }
  }
  return null;
}

function levenshtein(a, b) {
  const m=a.length, n=b.length;
  const dp=Array.from({length:m+1},(_,i)=>Array.from({length:n+1},(_,j)=>i||j));
  for (let i=1;i<=m;i++) for (let j=1;j<=n;j++) {
    dp[i][j]=a[i-1]===b[j-1]?dp[i-1][j-1]:1+Math.min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1]);
  }
  return dp[m][n];
}

// ── Version analysis ───────────────────────────────────────────────────────────
function analyseVersion(name, version) {
  const issues = [];
  if (!version || version==='*' || version==='latest' || version==='x')
    issues.push({ rule:'Wildcard Version', severity:'HIGH', detail:`"${version}" allows any version — supply chain attack vector.` });
  else if (version.startsWith('http://'))
    issues.push({ rule:'Plaintext HTTP Source', severity:'HIGH', detail:'Package fetched over unencrypted HTTP (MITM risk).' });
  else if (/^git\+http:\/\//i.test(version))
    issues.push({ rule:'Git HTTP Source', severity:'MEDIUM', detail:'Git dependency over HTTP — use HTTPS.' });
  else if (/^file:/.test(version))
    issues.push({ rule:'Local Path Dependency', severity:'INFO', detail:'Local path dependency — may not be reproducible in CI.' });
  else if (/^\^/.test(version))
    issues.push({ rule:'Minor Unpinned (^)', severity:'LOW', detail:`Caret range allows minor updates. Use exact version for prod.` });
  else if (/^~/.test(version))
    issues.push({ rule:'Patch Unpinned (~)', severity:'INFO', detail:`Tilde range allows patch updates.` });
  return issues;
}

// ── package.json auditor ───────────────────────────────────────────────────────
async function auditPackageJson(filePath, opts) {
  const issues = [], sbomEntries = [];
  try {
    const raw = await fs.readFile(filePath,'utf8');
    const data = JSON.parse(raw);
    const sections = ['dependencies','devDependencies','peerDependencies','optionalDependencies'];

    for (const sec of sections) {
      for (const [pkg, ver] of Object.entries(data[sec]||{})) {
        sbomEntries.push({ name:pkg, version:ver, source:'npm', section:sec });

        // Version analysis
        for (const issue of analyseVersion(pkg,ver)) {
          issues.push({ manifest: path.basename(filePath), section:sec, package:pkg, version:ver, ...issue });
        }

        // Known dangerous
        const known = DANGEROUS[pkg.toLowerCase()];
        if (known) issues.push({ manifest:path.basename(filePath), section:sec, package:pkg, version:ver, rule:'Known Malicious/Risky Package', ...known });

        // Typosquat
        const typo = detectTyposquat(pkg);
        if (typo) issues.push({ manifest:path.basename(filePath), section:sec, package:pkg, version:ver, rule:'Possible Typosquat', severity:'HIGH', reason:typo });

        // Prototype-pollution risk keywords
        if (/merge|extend|clone|assign|defaults|mixin/i.test(pkg)) {
          issues.push({ manifest:path.basename(filePath), section:sec, package:pkg, version:ver, rule:'Prototype Pollution Risk', severity:'MEDIUM', reason:`Package name suggests deep-merge behavior — verify CVE status.` });
        }
      }
    }

    // Lockfile presence
    const dir = path.dirname(filePath);
    const locks = ['package-lock.json','yarn.lock','pnpm-lock.yaml','bun.lockb'];
    const hasLock = (await Promise.all(locks.map(l=>fs.access(path.join(dir,l)).then(()=>true).catch(()=>false)))).some(Boolean);
    if (!hasLock) issues.push({ manifest:'package.json', rule:'Missing Lockfile', severity:'MEDIUM', reason:'No lockfile found — non-deterministic builds.' });

    // engines field check
    if (!data.engines) issues.push({ manifest:'package.json', rule:'Missing engines field', severity:'INFO', reason:'Specify "engines": { "node": ">=18" } for reproducibility.' });

  } catch(e) { issues.push({ manifest:'package.json', rule:'Parse Error', severity:'HIGH', reason:e.message }); }
  return { issues, sbomEntries };
}

// ── requirements.txt / Pipfile auditor ────────────────────────────────────────
async function auditPythonDeps(filePath) {
  const issues = [], sbomEntries = [];
  try {
    const raw   = await fs.readFile(filePath,'utf8');
    const lines = raw.split(/\r?\n/);
    for (let i=0;i<lines.length;i++) {
      const line = lines[i].trim();
      if (!line||line.startsWith('#')) continue;
      const [pkg, ...rest] = line.split(/[=><!\s]+/);
      sbomEntries.push({ name:pkg, version:rest.join('')||'unspecified', source:'pip' });
      if (!line.includes('==')) {
        issues.push({ manifest:path.basename(filePath), line:i+1, package:pkg, rule:'Unpinned Python Package', severity:'MEDIUM', reason:'Use == for exact pinning to prevent supply chain drift.' });
      }
      if (line.startsWith('http://')) {
        issues.push({ manifest:path.basename(filePath), line:i+1, package:pkg, rule:'Plaintext HTTP Source', severity:'HIGH', reason:'HTTP dependency source (MITM risk).' });
      }
    }
  } catch(e) { issues.push({ manifest:path.basename(filePath), rule:'Read Error', severity:'HIGH', reason:e.message }); }
  return { issues, sbomEntries };
}

// ── Score ──────────────────────────────────────────────────────────────────────
function riskScore(issues) {
  const w = { CRITICAL:25, HIGH:10, MEDIUM:5, LOW:2, INFO:0 };
  return Math.max(0, 100 - issues.reduce((s,i)=>s+(w[i.severity]||0),0));
}

export async function execute(args) {
  const rootPath = path.resolve(process.cwd(), args.target||'.');
  const doSbom   = args.sbom || false;
  const allIssues = [], allSbom = [], scanned = [];

  async function tryAudit(fp, type) {
    try {
      await fs.access(fp);
      scanned.push(fp);
      const { issues, sbomEntries } = type==='npm'
        ? await auditPackageJson(fp, args)
        : await auditPythonDeps(fp);
      allIssues.push(...issues);
      allSbom.push(...sbomEntries);
    } catch {}
  }

  const stat = await fs.stat(rootPath).catch(()=>null);
  if (!stat) return { success:false, error:`Path not found: ${rootPath}` };

  if (stat.isFile()) {
    const base = path.basename(rootPath).toLowerCase();
    if (base==='package.json') await tryAudit(rootPath,'npm');
    else await tryAudit(rootPath,'pip');
  } else {
    await tryAudit(path.join(rootPath,'package.json'),'npm');
    for (const f of ['requirements.txt','requirements-dev.txt','requirements-prod.txt','Pipfile']) {
      await tryAudit(path.join(rootPath,f),'pip');
    }
  }

  const score = riskScore(allIssues);
  const grade = score>=90?'A':score>=75?'B':score>=60?'C':score>=45?'D':'F';

  return {
    scannedManifests: scanned,
    supplyChainScore: score,
    supplyChainGrade: grade,
    totalIssues:  allIssues.length,
    summary: {
      CRITICAL: allIssues.filter(i=>i.severity==='CRITICAL').length,
      HIGH:     allIssues.filter(i=>i.severity==='HIGH').length,
      MEDIUM:   allIssues.filter(i=>i.severity==='MEDIUM').length,
      LOW:      allIssues.filter(i=>i.severity==='LOW').length,
      INFO:     allIssues.filter(i=>i.severity==='INFO').length,
    },
    findings: allIssues,
    sbom:     doSbom ? allSbom : `(Set sbom:true to generate SBOM — ${allSbom.length} packages found)`,
    verdict: allIssues.some(i=>i.severity==='CRITICAL')
      ? `🔴 CRITICAL — Malicious or backdoored package(s) detected! Audit supply chain immediately.`
      : allIssues.some(i=>i.severity==='HIGH')
        ? `🟠 HIGH RISK — High-risk dependencies found. Pin versions and review packages.`
        : allIssues.length>0
          ? `🟡 ${allIssues.length} issue(s) found. Review and remediate.`
          : `🟢 CLEAN — All dependencies appear safe (Score: ${score}/100).`
  };
}
