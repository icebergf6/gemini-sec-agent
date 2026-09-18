import fs from 'fs/promises';
import path from 'path';

export const declaration = {
  name: 'log_hunter',
  description: 'Overpower SOC threat hunter: 15 attack signatures, MITRE ATT&CK mapping, IP reputation scoring, brute-force timeline, attack kill-chain grouping, and auto-remediation playbooks.',
  parameters: {
    type: 'OBJECT',
    properties: {
      logPath:     { type: 'STRING',  description: 'Path to log file (access.log, auth.log, nginx.log, syslog, IIS log)' },
      logContent:  { type: 'STRING',  description: 'Raw log text (use this for piped/inline content)' },
      maxEntries:  { type: 'INTEGER', description: 'Max lines to analyse (default: 10000)' },
      mode:        { type: 'STRING',  description: '"web" (HTTP logs) | "auth" (SSH/auth.log) | "auto" (default: auto-detect)' },
      minSeverity: { type: 'STRING',  description: 'Minimum severity to include: CRITICAL|HIGH|MEDIUM|LOW (default: LOW)' },
    },
    required: []
  }
};

// ── MITRE ATT&CK mapping ───────────────────────────────────────────────────────
const SIGNATURES = [
  {
    id: 'T1190', type: 'SQL_INJECTION', severity: 'HIGH',
    mitre: 'T1190 – Exploit Public-Facing Application',
    regex: /(?:union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|truncate\s+table|or\s+['"]?1['"]?\s*=\s*['"]?1|waitfor\s+delay|sleep\(\d+\)|benchmark\(\d+|information_schema|pg_sleep|xp_cmdshell|--\s*$)/i,
    remediation: 'Use parameterised queries / prepared statements. Deploy WAF rule for SQLi patterns.'
  },
  {
    id: 'T1059', type: 'CROSS_SITE_SCRIPTING', severity: 'HIGH',
    mitre: 'T1059.007 – JavaScript Injection',
    regex: /(?:<script[\s>]|javascript:|vbscript:|onerror\s*=|onload\s*=|onfocus\s*=|alert\s*\(|confirm\s*\(|prompt\s*\(|<svg[\s>]|<img[^>]+onerror|document\.cookie|document\.write|eval\s*\()/i,
    remediation: 'Apply output encoding, strict CSP with nonces, and input validation.'
  },
  {
    id: 'T1083', type: 'PATH_TRAVERSAL_LFI', severity: 'HIGH',
    mitre: 'T1083 – File and Directory Discovery',
    regex: /(?:\.\.[\/\\]|%2e%2e[%2f\/\\]|%252e%252e|\/etc\/passwd|\/etc\/shadow|\/proc\/self\/environ|win\.ini|boot\.ini|web\.config|\.\.%5c)/i,
    remediation: 'Validate file paths, use chroot jails, and blocklist traversal patterns.'
  },
  {
    id: 'T1059.004', type: 'COMMAND_INJECTION', severity: 'CRITICAL',
    mitre: 'T1059.004 – Unix Shell Command Injection',
    regex: /(?:;\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|nc|ncat|python|perl|ruby|php)\b|\|\s*(?:cat|whoami|sh|bash)\b|\$\((?:whoami|id|cat|ls|curl)\b|`(?:whoami|id|ls)`|\bcmd\.exe\b|\bpowershell\b|\bpowershell\.exe\b)/i,
    remediation: 'Never pass user input to shell. Use exec arrays, not shell strings.'
  },
  {
    id: 'T1552.004', type: 'SSRF_CLOUD_METADATA', severity: 'CRITICAL',
    mitre: 'T1552.004 – Cloud Instance Metadata',
    regex: /(?:169\.254\.169\.254|metadata\.google\.internal|fd00:ec2|latest\/meta-data|latest\/user-data|iam\/security-credentials)/i,
    remediation: 'Block outbound requests to 169.254.169.254 in firewall/WAF. Use IMDSv2 on AWS.'
  },
  {
    id: 'T1110', type: 'BRUTE_FORCE_AUTH', severity: 'HIGH',
    mitre: 'T1110 – Brute Force',
    regex: /(?:failed password|authentication failure|invalid user|login failed|logon failure|too many auth|unauthorized|401 \d+|403 \d+)/i,
    remediation: 'Implement account lockout, MFA, and IP rate-limiting.'
  },
  {
    id: 'T1046', type: 'PORT_SCAN_PROBE', severity: 'MEDIUM',
    mitre: 'T1046 – Network Service Scanning',
    regex: /(?:nmap|masscan|zgrab|shodan|censys|nikto|dirbuster|gobuster|sqlmap|hydra|medusa|wfuzz|ffuf|nuclei)/i,
    remediation: 'Block known scanner User-Agents in WAF. Alert on rapid 404 patterns.'
  },
  {
    id: 'T1595', type: 'WEB_ENUMERATION', severity: 'MEDIUM',
    mitre: 'T1595 – Active Scanning / Fuzzing',
    regex: /(?:\.git\/|\.env|\.htaccess|\.htpasswd|wp-config\.php|config\.php|database\.yml|\.DS_Store|composer\.json|phpinfo\.php|\.aws\/credentials|app\.config|web\.config\.bak|backup\.sql|dump\.sql)/i,
    remediation: 'Deny access to config files via .htaccess/nginx rules. Run git-leak scans.'
  },
  {
    id: 'T1190.XXE', type: 'XXE_INJECTION', severity: 'HIGH',
    mitre: 'T1190 – XXE / XML Injection',
    regex: /(?:<!ENTITY|SYSTEM\s+["'](?:file|http|ftp|php|expect)|<!DOCTYPE[^>]+SYSTEM)/i,
    remediation: 'Disable external entity processing in XML parsers. Use JSON over XML.'
  },
  {
    id: 'T1134', type: 'LOG4SHELL_JNDI', severity: 'CRITICAL',
    mitre: 'T1134 – Log4Shell (CVE-2021-44228)',
    regex: /(?:\$\{jndi:|%24%7Bjndi:|%24%7Bjndi%3A|\$\{::-j\}|\$\{lower:j\})/i,
    remediation: 'Patch Log4j to ≥ 2.17.1. Block ${jndi: in WAF. Rotate all secrets.'
  },
  {
    id: 'T1059.007-proto', type: 'PROTOTYPE_POLLUTION', severity: 'HIGH',
    mitre: 'T1059 – Prototype Pollution',
    regex: /(?:__proto__|constructor\.prototype|Object\.prototype\[)/i,
    remediation: 'Use Object.freeze(Object.prototype). Sanitize JSON keys server-side.'
  },
  {
    id: 'T1078', type: 'DEFAULT_CREDENTIALS', severity: 'HIGH',
    mitre: 'T1078 – Valid/Default Accounts',
    regex: /(?:admin:admin|admin:password|root:root|test:test|admin:1234|user:user|guest:guest)/i,
    remediation: 'Remove default credentials. Enforce strong password policy and MFA.'
  },
  {
    id: 'T1498', type: 'DDOS_INDICATOR', severity: 'MEDIUM',
    mitre: 'T1498 – Network Denial of Service',
    regex: /(?:slowloris|loic|hoic|syn flood|udp flood|http flood|RUDY|r-u-dead-yet)/i,
    remediation: 'Deploy rate limiting, SYN cookies, and upstream DDoS scrubbing.'
  },
  {
    id: 'T1036', type: 'MASQUERADING_UA', severity: 'MEDIUM',
    mitre: 'T1036 – Masquerading User-Agent',
    regex: /(?:python-requests|go-http-client|curl\/[0-9]|libwww-perl|java\/[0-9]|scrapy|mechanize|headless|phantomjs|selenium)/i,
    remediation: 'Block known automation UAs in WAF. Add bot challenge (CAPTCHA).'
  }
];

const SEV_ORDER = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4 };

function parseIPFromLine(line) {
  const m = line.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
  return m ? m[1] : null;
}

function parseHttpStatus(line) {
  const m = line.match(/\s([1-5]\d{2})\s/);
  return m ? m[1] : null;
}

function parseTimestamp(line) {
  // Common Log Format: 01/Jan/2024:12:00:00
  const clf = line.match(/\[(\d{2}\/\w+\/\d{4}:\d{2}:\d{2}:\d{2})/);
  if (clf) return clf[1];
  // ISO
  const iso = line.match(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/);
  return iso ? iso[1] : null;
}

function detectMode(content) {
  if (/failed password|invalid user|accepted publickey|session opened/i.test(content)) return 'auth';
  return 'web';
}

function buildPlaybook(type) {
  const playbooks = {
    SQL_INJECTION:      '1. Check WAF logs for pattern. 2. Review DB query logs. 3. Rotate DB credentials. 4. Enable parameterised query enforcement.',
    COMMAND_INJECTION:  '1. Isolate affected host. 2. Review bash_history & auth.log. 3. Check for new cron jobs / startup scripts. 4. Redeploy from clean image.',
    LOG4SHELL_JNDI:     '1. IMMEDIATELY patch Log4j. 2. Check outbound DNS/JNDI connections. 3. Assume compromise — rotate ALL secrets. 4. Engage IR team.',
    SSRF_CLOUD_METADATA:'1. Block outbound 169.254.169.254 NOW. 2. Rotate cloud IAM credentials. 3. Enable IMDSv2 (AWS). 4. Review cloud audit logs.',
    BRUTE_FORCE_AUTH:   '1. Block offending IPs. 2. Enable MFA. 3. Increase lockout threshold. 4. Review for successful logins from same IP.',
    WEB_ENUMERATION:    '1. Review rules for config-file access. 2. Run secret-scanner on repo. 3. Rotate any exposed credentials. 4. Block scanner UA in WAF.',
  };
  return playbooks[type] || 'Review incident, isolate affected service, and notify security team.';
}

export async function execute(args) {
  let content = args.logContent || '';
  if (!content && args.logPath) {
    const fp = path.resolve(process.cwd(), args.logPath);
    try { content = await fs.readFile(fp, 'utf8'); }
    catch (e) { return { success: false, error: `Cannot read log: ${e.message}` }; }
  }
  if (!content) return { success: false, error: 'Provide logPath or logContent parameter.' };

  const minSev   = args.minSeverity?.toUpperCase() || 'LOW';
  const maxLines  = args.maxEntries || 10000;
  const lines     = content.split(/\r?\n/).filter(Boolean).slice(0, maxLines);
  const mode      = args.mode === 'auto' || !args.mode ? detectMode(content) : args.mode;

  const incidents  = [];
  const ipStats    = {};      // ip → { count, statuses, firstSeen, lastSeen, hitTypes }
  const statusMap  = {};
  const catSummary = {};

  for (let idx = 0; idx < lines.length; idx++) {
    const raw = lines[idx];
    let decoded = raw;
    try { decoded = decodeURIComponent(raw); } catch {}

    const ip  = parseIPFromLine(raw) || 'Unknown';
    const ts  = parseTimestamp(raw);
    const st  = parseHttpStatus(raw);

    // IP tracking
    if (!ipStats[ip]) ipStats[ip] = { count:0, statusCodes:{}, hitTypes:new Set(), firstSeen:ts, lastSeen:ts };
    ipStats[ip].count++;
    if (ts) ipStats[ip].lastSeen = ts;
    if (st) ipStats[ip].statusCodes[st] = (ipStats[ip].statusCodes[st]||0)+1;
    if (st) statusMap[st] = (statusMap[st]||0)+1;

    // Signature matching
    for (const sig of SIGNATURES) {
      if (SEV_ORDER[sig.severity] > SEV_ORDER[minSev]) continue;
      if (sig.regex.test(decoded) || sig.regex.test(raw)) {
        catSummary[sig.type] = (catSummary[sig.type]||0)+1;
        ipStats[ip].hitTypes.add(sig.type);
        incidents.push({
          lineNum:  idx+1,
          ip,
          ts,
          type:     sig.type,
          mitre:    sig.mitre,
          severity: sig.severity,
          snippet:  raw.length>220 ? raw.slice(0,217)+'…' : raw,
          remediation: sig.remediation
        });
        break; // one incident per line
      }
    }
  }

  // Brute-force IP analysis
  const bruteIPs = Object.entries(ipStats)
    .filter(([ip, s]) => s.count > 20 || (s.statusCodes['401']||0) > 5 || (s.statusCodes['403']||0) > 10)
    .map(([ip, s]) => ({
      ip,
      totalRequests: s.count,
      failedAuths:   (s.statusCodes['401']||0) + (s.statusCodes['403']||0),
      attackTypes:   [...s.hitTypes],
      firstSeen:     s.firstSeen,
      lastSeen:      s.lastSeen,
      riskScore:     Math.min(100, s.count/2 + (s.statusCodes['401']||0)*5),
      action:        s.count > 100 ? 'BLOCK NOW' : 'MONITOR'
    }))
    .sort((a,b) => b.riskScore - a.riskScore)
    .slice(0, 20);

  // Kill-chain grouping
  const killChain = {};
  for (const [ip, s] of Object.entries(ipStats)) {
    const types = [...s.hitTypes];
    if (types.length >= 2) {
      killChain[ip] = { phases: types, requestCount: s.count, verdict: '⚠ Multi-stage attack pattern detected!' };
    }
  }

  // Top incidents by severity
  const sortedIncidents = incidents
    .sort((a,b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])
    .slice(0, 50);

  // Playbooks for top attack types
  const playbooks = {};
  for (const type of Object.keys(catSummary).slice(0,5)) {
    playbooks[type] = buildPlaybook(type);
  }

  const critCount = incidents.filter(i=>i.severity==='CRITICAL').length;
  const highCount = incidents.filter(i=>i.severity==='HIGH').length;

  return {
    mode,
    linesAnalysed: lines.length,
    totalThreatsFound: incidents.length,
    findingsByCategory: catSummary,
    findingsBySeverity: {
      CRITICAL: critCount,
      HIGH:     highCount,
      MEDIUM:   incidents.filter(i=>i.severity==='MEDIUM').length,
      LOW:      incidents.filter(i=>i.severity==='LOW').length,
    },
    httpStatusCodes:   statusMap,
    suspiciousIPs:     bruteIPs,
    multiStageAttacks: killChain,
    remediationPlaybooks: playbooks,
    topIncidents: sortedIncidents,
    verdict: critCount > 0
      ? `🔴 CRITICAL THREAT — ${critCount} critical attack(s) detected. Activate IR plan immediately!`
      : highCount > 0
        ? `🟠 HIGH RISK — ${highCount} high-severity threat(s) found. Review & block attackers.`
        : incidents.length > 0
          ? `🟡 THREATS DETECTED — ${incidents.length} incident(s) found. Investigate suspicious IPs.`
          : `🟢 CLEAN — No attack signatures found in ${lines.length} log entries.`
  };
}
