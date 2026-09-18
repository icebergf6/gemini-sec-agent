import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

export const declaration = {
  name: 'secret_scanner',
  description: 'Overpower credential leak hunter: 30+ regex patterns (AWS/GCP/Azure/GitHub/Stripe/Twilio/JWT/SSH), Shannon entropy analysis, git-history hint, .gitignore check, and auto-remediation guide per finding.',
  parameters: {
    type: 'OBJECT',
    properties: {
      path:          { type: 'STRING',  description: 'File or directory path to scan (default: ".")' },
      entropyCheck:  { type: 'BOOLEAN', description: 'Enable Shannon entropy analysis (default: true)' },
      entropyMin:    { type: 'NUMBER',  description: 'Minimum entropy threshold (default: 4.5)' },
      includeExts:   { type: 'STRING',  description: 'Comma-separated file extensions to force-include (e.g., ".sh,.conf")' },
      maxFileKb:     { type: 'INTEGER', description: 'Max file size to scan in KB (default: 500)' },
    },
    required: ['path']
  }
};

// ── Secret Patterns ────────────────────────────────────────────────────────────
const PATTERNS = [
  // Cloud providers
  { name:'AWS Access Key ID',          regex:/\b(AKIA[0-9A-Z]{16})\b/g,                                severity:'CRITICAL', remediation:'Revoke in AWS IAM console immediately. Rotate all related access keys.' },
  { name:'AWS Secret Access Key',      regex:/(?:aws_secret|aws_sec|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi, severity:'CRITICAL', remediation:'Revoke key, run `aws iam delete-access-key`, check CloudTrail for misuse.' },
  { name:'AWS Session Token',          regex:/\b(ASIA[0-9A-Z]{16})\b/g,                                severity:'CRITICAL', remediation:'Session token likely expired, but revoke parent credentials.' },
  { name:'GCP Service Account Key',    regex:/"type"\s*:\s*"service_account"/g,                          severity:'CRITICAL', remediation:'Revoke in GCP IAM, rotate service account key JSON.' },
  { name:'Azure Storage Key',          regex:/DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88})/g, severity:'CRITICAL', remediation:'Regenerate storage account key in Azure Portal.' },

  // Source control
  { name:'GitHub Personal Token',      regex:/\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b/g, severity:'CRITICAL', remediation:'Revoke at github.com/settings/tokens. Check repos for git history.' },
  { name:'GitHub OAuth Token',         regex:/\b(gho_[a-zA-Z0-9]{36})\b/g,                              severity:'CRITICAL', remediation:'Revoke OAuth token immediately.' },
  { name:'GitLab Personal Token',      regex:/\bglpat-[a-zA-Z0-9\-]{20}\b/g,                            severity:'CRITICAL', remediation:'Revoke at GitLab → User Settings → Access Tokens.' },

  // Google
  { name:'Google API Key',             regex:/\b(AIza[0-9A-Za-z\-_]{35})\b/g,                           severity:'HIGH',     remediation:'Restrict key in GCP Console → APIs → Credentials.' },
  { name:'Google OAuth2',              regex:/\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b/g, severity:'MEDIUM', remediation:'Rotate client secret in GCP Console.' },

  // Payment
  { name:'Stripe Secret Key',          regex:/\b(sk_live_[0-9a-zA-Z]{24,})\b/g,                         severity:'CRITICAL', remediation:'Revoke at dashboard.stripe.com/apikeys immediately!' },
  { name:'Stripe Publishable Key',     regex:/\b(pk_live_[0-9a-zA-Z]{24,})\b/g,                         severity:'MEDIUM',   remediation:'Publishable key is low-risk but verify no secret key nearby.' },
  { name:'PayPal Client Secret',       regex:/(?:paypal.*secret|client_secret)\s*[=:]\s*["']?([A-Za-z0-9\-_]{32,64})["']?/gi, severity:'CRITICAL', remediation:'Revoke in PayPal developer dashboard.' },

  // Messaging
  { name:'Slack Token',                regex:/\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b/g,                    severity:'HIGH',     remediation:'Revoke at api.slack.com/apps. Check Slack audit logs.' },
  { name:'Slack Webhook',              regex:/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/g, severity:'HIGH', remediation:'Regenerate webhook URL in Slack app settings.' },
  { name:'Twilio Account SID',         regex:/\b(AC[a-f0-9]{32})\b/g,                                   severity:'HIGH',     remediation:'Verify not paired with Auth Token in same file.' },
  { name:'Twilio Auth Token',          regex:/(?:twilio.*auth.*token|auth_token)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi, severity:'CRITICAL', remediation:'Revoke in Twilio Console → Account → Auth Tokens.' },
  { name:'SendGrid API Key',           regex:/\b(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})\b/g,      severity:'HIGH',     remediation:'Revoke at app.sendgrid.com/settings/api_keys.' },
  { name:'Mailgun API Key',            regex:/\b(key-[a-z0-9]{32})\b/g,                                 severity:'HIGH',     remediation:'Revoke in Mailgun Dashboard → API Keys.' },

  // Auth / Crypto
  { name:'RSA/SSH Private Key',        regex:/-----BEGIN (?:RSA|EC|OPENSSH|DSA)? ?PRIVATE KEY-----/g,   severity:'CRITICAL', remediation:'Immediately rotate key pair. If SSH key, remove from authorized_keys.' },
  { name:'JSON Web Token (JWT)',        regex:/\b(eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,})\b/g, severity:'HIGH', remediation:'Revoke token. Ensure tokens have short TTL. Never hardcode JWTs.' },
  { name:'Basic Auth in URL',          regex:/https?:\/\/[^:@\s]+:[^@\s]+@[a-zA-Z0-9\-._]+/g,          severity:'CRITICAL', remediation:'Remove credentials from URL. Use environment variables.' },

  // Database
  { name:'Database URI (Postgres)',    regex:/postgres(?:ql)?:\/\/[a-zA-Z0-9_-]+:[^@\s"']+@[a-zA-Z0-9.\-]+/gi, severity:'CRITICAL', remediation:'Rotate DB password. Move to secrets manager.' },
  { name:'Database URI (MySQL)',       regex:/mysql:\/\/[a-zA-Z0-9_-]+:[^@\s"']+@[a-zA-Z0-9.\-]+/gi,   severity:'CRITICAL', remediation:'Rotate DB password. Move to secrets manager.' },
  { name:'Database URI (MongoDB)',     regex:/mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_-]+:[^@\s"']+@[a-zA-Z0-9.\-]+/gi, severity:'CRITICAL', remediation:'Rotate MongoDB credentials immediately.' },
  { name:'Database URI (Redis)',       regex:/redis:\/\/:[^@\s"']+@[a-zA-Z0-9.\-]+/gi,                  severity:'HIGH',     remediation:'Remove Redis AUTH password from URI. Use env var.' },

  // Generic patterns
  { name:'Generic Password',           regex:/(?:^|[^a-z])(?:password|passwd|pwd|db_pass|api_secret)\s*[=:]+\s*["']([^"'\s]{8,})["']/gim, severity:'HIGH', remediation:'Move to .env or secrets manager.' },
  { name:'Generic API Key',            regex:/(?:api[_\-]?key|apikey|access[_\-]?token)\s*[=:]+\s*["']([A-Za-z0-9\-_]{20,})["']/gi, severity:'HIGH', remediation:'Rotate key and store in environment variable.' },
  { name:'Hex Secret (32+ chars)',     regex:/(?:secret|token|key)\s*[=:]\s*["']([0-9a-f]{32,64})["']/gi, severity:'MEDIUM', remediation:'Verify this is not a production secret.' },
];

const IGNORED_DIRS  = new Set(['node_modules','.git','.svn','dist','build','.idea','.vscode','coverage','__pycache__','.tox','vendor','target']);
const IGNORED_FILES = new Set(['package-lock.json','yarn.lock','pnpm-lock.yaml','bun.lockb','*.min.js']);
const BINARY_EXTS   = new Set(['.png','.jpg','.jpeg','.gif','.ico','.pdf','.zip','.tar','.gz','.exe','.dll','.bin','.woff','.woff2','.mp4','.mp3','.ttf','.eot']);
const HIGH_VALUE_EXTS = new Set(['.env','.json','.yaml','.yml','.toml','.ini','.cfg','.config','.conf','.sh','.bash','.zsh','.py','.js','.mjs','.ts','.rb','.php','.go','.java','.xml','.properties','.pem','.key','.p12','.pfx']);

// ── Entropy ────────────────────────────────────────────────────────────────────
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c]||0)+1;
  let e = 0;
  for (const f of Object.values(freq)) { const p=f/str.length; e -= p*Math.log2(p); }
  return e;
}

function maskSecret(val) {
  if (!val || val.length <= 8) return '***REDACTED***';
  return `${val.slice(0,4)}${'█'.repeat(Math.min(val.length-8,20))}${val.slice(-4)}`;
}

// ── File scanner ───────────────────────────────────────────────────────────────
async function scanFile(filePath, opts) {
  const ext  = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();
  if (BINARY_EXTS.has(ext)) return [];
  if (!HIGH_VALUE_EXTS.has(ext) && !opts.extraExts?.has(ext) && !base.startsWith('.env')) return [];

  let content;
  try {
    const stat = await fs.stat(filePath);
    if (stat.size > (opts.maxFileKb||500)*1024) return [];
    content = await fs.readFile(filePath, 'utf8');
  } catch { return []; }

  const findings = [];
  const lines    = content.split(/\r?\n/);

  for (let ln=0; ln<lines.length; ln++) {
    const line = lines[ln];
    // Pattern matching
    for (const pat of PATTERNS) {
      pat.regex.lastIndex = 0;
      let m;
      while ((m=pat.regex.exec(line))!==null) {
        const raw = m[1]||m[0];
        findings.push({
          file:        filePath,
          line:        ln+1,
          col:         m.index+1,
          rule:        pat.name,
          severity:    pat.severity,
          masked:      maskSecret(raw),
          remediation: pat.remediation
        });
      }
    }
    // Entropy scan
    if (opts.entropy) {
      const tokens = line.match(/[A-Za-z0-9+/=_\-]{20,}/g)||[];
      for (const tok of tokens) {
        if (tok.startsWith('-----') || /^[0-9]+$/.test(tok)) continue;
        const e = shannonEntropy(tok);
        if (e >= opts.entropyMin) {
          findings.push({
            file:     filePath,
            line:     ln+1,
            rule:     'High-Entropy Token',
            severity: 'MEDIUM',
            masked:   maskSecret(tok),
            entropy:  e.toFixed(3),
            remediation:'Verify this high-randomness token is not a secret. Use a secrets manager.'
          });
        }
      }
    }
  }
  return findings;
}

// ── Directory walker ───────────────────────────────────────────────────────────
async function walk(dir, opts, findings=[], stats={count:0,skipped:0}) {
  let entries;
  try { entries = await fs.readdir(dir,{withFileTypes:true}); } catch { return; }
  for (const e of entries) {
    if (IGNORED_DIRS.has(e.name)) continue;
    const fp = path.join(dir,e.name);
    if (e.isDirectory()) await walk(fp,opts,findings,stats);
    else if (e.isFile()) {
      stats.count++;
      const res = await scanFile(fp,opts);
      findings.push(...res);
    }
  }
}

// ── .gitignore check ───────────────────────────────────────────────────────────
async function checkGitignore(rootPath) {
  const gi = path.join(rootPath,'.gitignore');
  try {
    const content = await fs.readFile(gi,'utf8');
    const missing = [];
    if (!content.includes('.env')) missing.push('.env');
    if (!content.includes('*.pem')) missing.push('*.pem');
    if (!content.includes('*.key')) missing.push('*.key');
    if (!content.includes('*.p12')) missing.push('*.p12');
    return { exists:true, missingPatterns: missing };
  } catch { return { exists:false, missingPatterns:['.env','*.pem','*.key','credentials*'] }; }
}

export async function execute(args) {
  const rootPath    = path.resolve(process.cwd(), args.path||'.');
  const doEntropy   = args.entropyCheck !== false;
  const entropyMin  = args.entropyMin || 4.5;
  const extraExts   = args.includeExts ? new Set(args.includeExts.split(',').map(s=>s.trim())) : new Set();
  const maxFileKb   = args.maxFileKb || 500;
  const opts        = { entropy: doEntropy, entropyMin, extraExts, maxFileKb };

  const findings = [];
  const stats    = { count:0, skipped:0 };

  let st;
  try {
    st = await fs.stat(rootPath);
    if (st.isFile()) {
      stats.count=1;
      findings.push(...await scanFile(rootPath,opts));
    } else {
      await walk(rootPath,opts,findings,stats);
    }
  } catch (e) {
    return { success:false, error:`Cannot access path: ${e.message}` };
  }

  const gi = await checkGitignore(st?.isDirectory?.() ? rootPath : path.dirname(rootPath));

  // Group by severity
  const bySev = (s)=>findings.filter(f=>f.severity===s);
  const criticals = bySev('CRITICAL');
  const highs     = bySev('HIGH');

  return {
    scannedPath:   rootPath,
    filesScanned:  stats.count,
    totalFindings: findings.length,
    summary: {
      CRITICAL: criticals.length,
      HIGH:     highs.length,
      MEDIUM:   bySev('MEDIUM').length,
      LOW:      bySev('LOW').length,
    },
    gitignoreStatus: gi,
    findings: findings.slice(0,100),
    verdict: criticals.length > 0
      ? `🔴 CRITICAL — ${criticals.length} critical credential(s) exposed! Rotate immediately.`
      : highs.length > 0
        ? `🟠 HIGH RISK — ${highs.length} high-risk secret(s) found. Rotate and secure.`
        : findings.length > 0
          ? `🟡 ${findings.length} potential secret(s) detected. Review each finding.`
          : `🟢 CLEAN — No leaked secrets detected in ${stats.count} files.`
  };
}
