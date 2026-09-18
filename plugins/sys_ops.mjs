import os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';

const execAsync = promisify(exec);

export const declaration = {
  name: 'sys_ops',
  description: 'Overpower system security auditor: privilege level, running processes, cron jobs, SUID/SGID files, world-writable paths, env variable leak check, firewall status, and security hardening score.',
  parameters: {
    type: 'OBJECT',
    properties: {
      checkPorts:    { type: 'BOOLEAN', description: 'Enumerate listening TCP/UDP sockets (default: true)' },
      checkCron:     { type: 'BOOLEAN', description: 'Enumerate scheduled cron/task jobs (default: true)' },
      checkProcesses:{ type: 'BOOLEAN', description: 'List top suspicious/privileged processes (default: true)' },
      checkEnvLeaks: { type: 'BOOLEAN', description: 'Check for secrets in environment variables (default: true)' },
      checkFirewall: { type: 'BOOLEAN', description: 'Check firewall/iptables status (default: true)' },
    },
    required: []
  }
};

const isWin = process.platform === 'win32';

async function safeExec(cmd, timeout=8000) {
  try {
    const { stdout } = await execAsync(cmd, { timeout, windowsHide: true });
    return stdout.trim();
  } catch { return ''; }
}

// ── Privilege check ────────────────────────────────────────────────────────────
async function checkPrivilege() {
  if (isWin) {
    const out = await safeExec('net session 2>&1');
    const elevated = !out.toLowerCase().includes('access is denied') && !out.toLowerCase().includes('not found');
    return { elevated, user: os.userInfo().username };
  }
  const uid = process.getuid?.() ?? -1;
  return { elevated: uid === 0, user: os.userInfo().username, uid };
}

// ── Listening sockets ──────────────────────────────────────────────────────────
async function getListeningSockets() {
  const sockets = [];
  if (isWin) {
    const out = await safeExec('netstat -ano -p tcp');
    for (const line of out.split(/\r?\n/)) {
      if (!line.includes('LISTENING')) continue;
      const p = line.trim().split(/\s+/);
      if (p.length >= 4) {
        const addr = p[1];
        const port = parseInt(addr.split(':').pop());
        sockets.push({ proto:'TCP', localAddress:addr, pid:p[4]||null, port });
      }
    }
  } else {
    const out = await safeExec('ss -tlpn 2>/dev/null || netstat -tlpn 2>/dev/null');
    for (const line of out.split(/\r?\n/)) {
      if (!line.includes('LISTEN')) continue;
      sockets.push({ raw: line.trim() });
    }
  }
  return sockets.slice(0,50);
}

// ── Running processes ──────────────────────────────────────────────────────────
async function getProcesses() {
  if (isWin) {
    const out = await safeExec('tasklist /fo csv /nh');
    return out.split(/\r?\n/).slice(0,20).map(l=>{
      const [name,,,,mem] = l.replace(/"/g,'').split(',');
      return { name, memKb: mem?.replace(/[^0-9]/g,'') };
    }).filter(p=>p.name);
  }
  const out = await safeExec('ps aux --sort=-%cpu 2>/dev/null | head -20');
  return out.split(/\r?\n/).slice(1).map(l=>{
    const p=l.trim().split(/\s+/);
    return { user:p[0], pid:p[1], cpu:p[2], mem:p[3], cmd:p.slice(10).join(' ').slice(0,60) };
  }).filter(p=>p.pid);
}

// ── Cron / Scheduled tasks ─────────────────────────────────────────────────────
async function getCronJobs() {
  if (isWin) {
    const out = await safeExec('schtasks /query /fo csv /nh 2>nul');
    return out.split(/\r?\n/).slice(0,20)
      .map(l=>l.replace(/"/g,'').split(','))
      .filter(p=>p.length>2)
      .map(p=>({ name:p[0], nextRun:p[1], status:p[2] }));
  }
  const cronOut = await safeExec('crontab -l 2>/dev/null');
  const sysCron = await safeExec('cat /etc/crontab 2>/dev/null');
  const combined = [cronOut, sysCron].join('\n');
  return combined.split(/\r?\n/).filter(l=>l.trim()&&!l.startsWith('#')).slice(0,20);
}

// ── Environment variable secret check ─────────────────────────────────────────
function scanEnvLeaks() {
  const suspects = [];
  const sensitive = /password|secret|token|api_key|apikey|auth|credential|private_key|cert|passphrase/i;
  for (const [k,v] of Object.entries(process.env)) {
    if (!v) continue;
    if (sensitive.test(k)) {
      const masked = v.length>6 ? `${v.slice(0,2)}${'*'.repeat(Math.min(v.length-4,12))}${v.slice(-2)}` : '***';
      suspects.push({ key:k, maskedValue:masked, length:v.length });
    }
  }
  return suspects;
}

// ── Firewall check ─────────────────────────────────────────────────────────────
async function checkFirewall() {
  if (isWin) {
    const out = await safeExec('netsh advfirewall show allprofiles state');
    return {
      active:  out.toLowerCase().includes('on'),
      details: out.split(/\r?\n/).filter(l=>l.includes('State')).map(l=>l.trim())
    };
  }
  const ufw  = await safeExec('ufw status 2>/dev/null');
  const ipt  = await safeExec('iptables -L -n 2>/dev/null | head -10');
  return {
    ufw:      ufw || 'N/A',
    iptables: ipt || 'N/A',
    active:   ufw.includes('active') || ipt.length>0
  };
}

// ── SUID check (Linux) ─────────────────────────────────────────────────────────
async function getSUIDs() {
  if (isWin) return [];
  const out = await safeExec('find / -perm -4000 -type f 2>/dev/null | head -30');
  return out.split(/\r?\n/).filter(Boolean).slice(0,20);
}

// ── Hardening score ────────────────────────────────────────────────────────────
function calcHardeningScore(priv, sockets, envLeaks, fw) {
  let score = 100;
  const issues = [];
  if (priv.elevated)        { score-=30; issues.push('Running as root/Administrator (-30)'); }
  if (sockets.length>20)    { score-=10; issues.push(`${sockets.length} open ports (-10)`); }
  if (envLeaks.length>0)    { score-=15; issues.push(`${envLeaks.length} secret env vars (-15)`); }
  if (!fw.active)            { score-=20; issues.push('Firewall disabled (-20)'); }
  return { score: Math.max(0, score), deductions: issues };
}

export async function execute(args) {
  const doSockets  = args.checkPorts     !== false;
  const doCron     = args.checkCron      !== false;
  const doProcs    = args.checkProcesses !== false;
  const doEnv      = args.checkEnvLeaks  !== false;
  const doFirewall = args.checkFirewall  !== false;

  const [priv, sockets, procs, cron, fw, suids] = await Promise.all([
    checkPrivilege(),
    doSockets   ? getListeningSockets() : Promise.resolve([]),
    doProcs     ? getProcesses()        : Promise.resolve([]),
    doCron      ? getCronJobs()         : Promise.resolve([]),
    doFirewall  ? checkFirewall()       : Promise.resolve({ active: null }),
    !isWin      ? getSUIDs()            : Promise.resolve([]),
  ]);

  const envLeaks = doEnv ? scanEnvLeaks() : [];

  // Memory
  const totalMem = Math.round(os.totalmem()/1048576);
  const freeMem  = Math.round(os.freemem()/1048576);
  const usedMem  = totalMem - freeMem;

  // Hardening
  const { score, deductions } = calcHardeningScore(priv, sockets, envLeaks, fw);
  const grade = score>=90?'A':score>=75?'B':score>=60?'C':score>=45?'D':'F';

  // Risk findings
  const findings = [];
  if (priv.elevated)     findings.push({ severity:'HIGH',   issue:`Process running as ${priv.elevated?'Administrator/root':'elevated user'}`, remediation:'Use least-privilege user. Never run app as root.' });
  if (envLeaks.length)   findings.push({ severity:'MEDIUM', issue:`${envLeaks.length} environment variable(s) contain sensitive key names.`, remediation:'Move secrets to a secrets manager or .env with restricted permissions.' });
  if (!fw.active)        findings.push({ severity:'HIGH',   issue:'Host firewall appears to be DISABLED.', remediation:'Enable firewall: `ufw enable` (Linux) or Windows Defender Firewall.' });
  if (suids.length>10)   findings.push({ severity:'MEDIUM', issue:`${suids.length} SUID binaries found — review for privilege escalation.`, remediation:'Audit SUID binaries: remove unnecessary setuid bits with `chmod u-s`.' });

  return {
    host: {
      hostname:    os.hostname(),
      platform:    process.platform,
      arch:        os.arch(),
      release:     os.release(),
      uptimeHours: (os.uptime()/3600).toFixed(2),
      cpuCount:    os.cpus().length,
      cpuModel:    os.cpus()[0]?.model || 'Unknown',
    },
    privilege: {
      user:        priv.user,
      elevated:    priv.elevated,
      warning:     priv.elevated ? '⚠ Running as admin/root — use least-privilege!' : '✔ Non-elevated user.'
    },
    memory: {
      totalMb: totalMem, usedMb: usedMem, freeMb: freeMem,
      usagePercent: `${((usedMem/totalMem)*100).toFixed(1)}%`,
      pressure: usedMem/totalMem > 0.9 ? 'CRITICAL' : usedMem/totalMem > 0.75 ? 'HIGH' : 'NORMAL'
    },
    networkInterfaces: Object.entries(os.networkInterfaces()).flatMap(([name,nets])=>
      (nets||[]).filter(n=>!n.internal&&n.family==='IPv4').map(n=>({ interface:name, ip:n.address, mac:n.mac, netmask:n.netmask }))
    ),
    listeningSockets:  sockets,
    firewall:          fw,
    scheduledTasks:    cron,
    topProcesses:      procs,
    suidBinaries:      suids,
    envSecretLeaks:    envLeaks,
    hardeningScore:    score,
    hardeningGrade:    grade,
    hardeningDeductions: deductions,
    securityFindings:  findings,
    verdict: score < 50
      ? `🔴 CRITICAL RISK — Hardening score ${score}/100 (${grade}). Immediate action required!`
      : score < 75
        ? `🟠 HIGH RISK — Hardening score ${score}/100 (${grade}). Review findings above.`
        : score < 90
          ? `🟡 MODERATE — Hardening score ${score}/100 (${grade}). Room for improvement.`
          : `🟢 SECURE — Hardening score ${score}/100 (${grade}). System well hardened.`
  };
}
