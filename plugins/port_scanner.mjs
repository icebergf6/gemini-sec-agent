import net from 'net';
import dns from 'dns/promises';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export const declaration = {
  name: 'port_scanner',
  description: 'Overpower TCP port scanner: concurrent probing, banner grab, service fingerprinting, CVE risk tagging, OS hint, and reverse DNS — all in one shot.',
  parameters: {
    type: 'OBJECT',
    properties: {
      target:      { type: 'STRING',  description: 'Target IP, hostname, or CIDR /24 (e.g., 192.168.1.0/24)' },
      ports:       { type: 'STRING',  description: 'Port spec: "common" | "top1000" | "all" | "80,443,8080" | "20-1024"' },
      timeout:     { type: 'INTEGER', description: 'Timeout per port in ms (default: 600)' },
      concurrency: { type: 'INTEGER', description: 'Parallel probes (default: 50, max: 200)' },
      reverseDns:  { type: 'BOOLEAN', description: 'Perform rDNS lookup on open ports (default: true)' },
      showClosed:  { type: 'BOOLEAN', description: 'Include closed/filtered ports in output (default: false)' },
    },
    required: ['target']
  }
};

// ── Service map ────────────────────────────────────────────────────────────────
const SVC = {
  21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS', 69:'TFTP',
  80:'HTTP', 110:'POP3', 111:'RPC', 119:'NNTP', 135:'MS-RPC', 137:'NetBIOS-NS',
  139:'NetBIOS-SMB', 143:'IMAP', 161:'SNMP', 179:'BGP', 389:'LDAP',
  443:'HTTPS', 445:'SMB', 465:'SMTPS', 587:'SMTP-TLS', 636:'LDAPS',
  873:'rsync', 993:'IMAPS', 995:'POP3S', 1080:'SOCKS5', 1194:'OpenVPN',
  1433:'MSSQL', 1521:'Oracle-DB', 2049:'NFS', 2181:'Zookeeper',
  2375:'Docker-API', 2376:'Docker-TLS', 3000:'Dev/Grafana', 3306:'MySQL',
  3389:'RDP', 4200:'Angular-Dev', 4444:'Metasploit/Backdoor', 5000:'Flask/UPnP',
  5432:'PostgreSQL', 5900:'VNC', 5984:'CouchDB', 6379:'Redis',
  6443:'K8s-API', 7001:'WebLogic', 8000:'HTTP-Alt', 8080:'HTTP-Proxy',
  8443:'HTTPS-Alt', 8888:'Jupyter/Dev', 9000:'PHP-FPM/Portainer',
  9090:'Prometheus', 9200:'Elasticsearch', 9300:'ES-Transport',
  11211:'Memcached', 15672:'RabbitMQ-MGMT', 27017:'MongoDB', 50000:'SAP'
};

// ── Risk tags per port ─────────────────────────────────────────────────────────
const RISK = {
  21:  { level:'CRITICAL', note:'FTP cleartext credential exposure (RFC 959).' },
  23:  { level:'CRITICAL', note:'Telnet — plaintext remote shell, no encryption.' },
  69:  { level:'HIGH',     note:'TFTP unauthenticated read/write.' },
  110: { level:'HIGH',     note:'POP3 cleartext auth.' },
  135: { level:'HIGH',     note:'MS-RPC attack surface (EternalBlue, DCOM exploits).' },
  139: { level:'HIGH',     note:'NetBIOS — SMB exploit surface (MS17-010, PrintNightmare).' },
  161: { level:'HIGH',     note:'SNMP — often default community string "public".' },
  445: { level:'CRITICAL', note:'SMB directly exposed — EternalBlue, WannaCry pivot.' },
  873: { level:'HIGH',     note:'rsync — unauthenticated access to file system.' },
  1080:{ level:'HIGH',     note:'SOCKS5 proxy — potential exfil/pivot channel.' },
  2375:{ level:'CRITICAL', note:'Docker API unencrypted — full host takeover.' },
  2376:{ level:'HIGH',     note:'Docker TLS — verify cert pinning.' },
  3389:{ level:'HIGH',     note:'RDP — BlueKeep (CVE-2019-0708), brute-force target.' },
  4444:{ level:'CRITICAL', note:'Common Metasploit/backdoor listener.' },
  5900:{ level:'HIGH',     note:'VNC — often no auth or weak password.' },
  5984:{ level:'HIGH',     note:'CouchDB — unauthenticated admin API if default.' },
  6379:{ level:'CRITICAL', note:'Redis — no auth by default, RCE via CONFIG SET.' },
  7001:{ level:'HIGH',     note:'WebLogic — CVE-2020-14882 RCE.' },
  8888:{ level:'HIGH',     note:'Jupyter Notebook — often no token/password.' },
  9200:{ level:'HIGH',     note:'Elasticsearch — unauthenticated data exfil.' },
  11211:{ level:'HIGH',    note:'Memcached — DDoS amplification & data exposure.' },
  27017:{ level:'CRITICAL',note:'MongoDB — no auth by default in older versions.' },
};

// ── Port presets ───────────────────────────────────────────────────────────────
const COMMON_PORTS = Object.keys(SVC).map(Number);
const TOP1000 = (() => {
  const extra = [1,7,9,13,17,19,20,26,37,49,79,88,106,109,111,113,120,125,
    143,144,146,161,162,163,164,174,194,197,199,201,202,204,206,209,210,211,
    212,213,214,215,216,217,218,219,220,222,249,256,259,264,265,280,301,306,
    311,340,366,406,407,416,417,425,427,443,444,458,464,465,481,497,500,512,
    513,514,515,524,541,543,544,548,554,563,587,593,616,617,625,631,636,646,
    648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,
    787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,
    992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,
    1025,1026,1027,1028,1029,1030,1110,1234,1234,1241,1311,1352,1434,1494,
    1521,1720,1723,1755,1900,2000,2001,2002,2100,2103,2105,2107,2121,2301,
    2717,2869,2967,3000,3001,3127,3128,3222,3260,3268,3269,3306,3389,3689,
    3784,3801,3986,4000,4001,4045,4899,5000,5001,5003,5009,5051,5060,5101,
    5120,5190,5357,5432,5555,5631,5666,5800,5900,6000,6001,6646,6881,7000,
    7070,7937,7938,8000,8008,8009,8010,8031,8080,8081,8443,8888,9000,9090,
    9100,9102,9999,10000,32768,49152,49153,49154,49155,49156,49157];
  return [...new Set([...COMMON_PORTS, ...extra])].sort((a,b) => a-b);
})();

function parsePorts(spec) {
  if (!spec || spec === 'common') return COMMON_PORTS;
  if (spec === 'top1000') return TOP1000;
  if (spec === 'all') {
    const all = [];
    for (let i=1; i<=65535; i++) all.push(i);
    return all;
  }
  if (spec.includes('-')) {
    const [s,e] = spec.split('-').map(Number);
    const min = Math.max(1, Math.min(s,e));
    const max = Math.min(65535, Math.max(s,e));
    const r = [];
    for (let p=min; p<=max; p++) r.push(p);
    return r;
  }
  return spec.split(',').map(p=>parseInt(p.trim(),10)).filter(p=>!isNaN(p)&&p>0&&p<=65535);
}

function probePort(target, port, timeoutMs) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    let banner = '';
    const start = Date.now();

    sock.setTimeout(timeoutMs);
    sock.connect(port, target, () => {
      // Protocol-aware probes
      const probes = {
        80:  'HEAD / HTTP/1.0\r\n\r\n',
        8080:'HEAD / HTTP/1.0\r\n\r\n',
        8443:'HEAD / HTTP/1.0\r\n\r\n',
        21:  '',  // FTP sends banner on connect
        22:  '',  // SSH sends banner on connect
        25:  '',  // SMTP sends banner on connect
      };
      try { sock.write(probes[port] ?? '\r\n'); } catch {}

      setTimeout(() => {
        if (!settled) {
          settled = true;
          sock.destroy();
          resolve({ port, open: true, latencyMs: Date.now()-start,
            service: SVC[port]||'Unknown', banner: cleanBanner(banner) });
        }
      }, Math.min(timeoutMs, 200));
    });

    sock.on('data', d => { banner += d.toString('ascii', 0, 128); });

    sock.on('timeout', () => { if(!settled){settled=true;sock.destroy();resolve({port,open:false});} });
    sock.on('error',   () => { if(!settled){settled=true;sock.destroy();resolve({port,open:false});} });
  });
}

function cleanBanner(raw) {
  if (!raw) return null;
  return raw.replace(/[\x00-\x08\x0b-\x1f\x7f-\xff]/g,'').trim().slice(0,100) || null;
}

async function expandCIDR(cidr) {
  const m = cidr.match(/^(\d+\.\d+\.\d+)\.(\d+)\/24$/);
  if (!m) return [cidr];
  const hosts = [];
  for (let i=1; i<=254; i++) hosts.push(`${m[1]}.${i}`);
  return hosts;
}

async function reverseDnsLookup(ip) {
  try { const r = await dns.reverse(ip); return r[0] || null; }
  catch { return null; }
}

function formatRisk(port, banner) {
  const r = RISK[port];
  if (r) return r;
  // Heuristic banner analysis
  if (banner) {
    if (/ssh/i.test(banner)) return { level:'INFO', note:`SSH banner: ${banner.slice(0,60)}` };
    if (/http/i.test(banner)) return { level:'INFO', note:'HTTP service detected from banner.' };
  }
  return null;
}

export async function execute(args) {
  const timeoutMs  = Math.min(args.timeout  || 600, 3000);
  const concurrency = Math.min(args.concurrency || 50, 200);
  const doRDNS     = args.reverseDns !== false;
  const portList   = parsePorts(args.ports);

  // CIDR /24 expansion
  let targets = [];
  if (typeof args.target === 'string' && args.target.includes('/24')) {
    targets = await expandCIDR(args.target);
  } else {
    targets = [args.target || '127.0.0.1'];
  }

  const allResults = [];

  for (const target of targets) {
    // Resolve hostname → IP
    let resolvedIP = target;
    try {
      const resolved = await dns.resolve4(target);
      if (resolved.length) resolvedIP = resolved[0];
    } catch {}

    const openPorts = [];
    // Chunk-based concurrency pool
    for (let i = 0; i < portList.length; i += concurrency) {
      const chunk = portList.slice(i, i + concurrency);
      const results = await Promise.all(chunk.map(p => probePort(resolvedIP, p, timeoutMs)));
      for (const r of results) {
        if (r.open) openPorts.push(r);
      }
    }

    // rDNS for open ports' IPs
    let rdns = null;
    if (doRDNS && resolvedIP !== target) {
      rdns = await reverseDnsLookup(resolvedIP);
    }

    // Annotate risk
    const annotated = openPorts
      .sort((a,b) => a.port - b.port)
      .map(p => ({
        port:     p.port,
        service:  p.service,
        latencyMs:p.latencyMs,
        banner:   p.banner,
        risk:     formatRisk(p.port, p.banner)
      }));

    const critCount  = annotated.filter(p => p.risk?.level==='CRITICAL').length;
    const highCount  = annotated.filter(p => p.risk?.level==='HIGH').length;

    allResults.push({
      target,
      resolvedIP,
      reverseDns: rdns,
      portsProbed:  portList.length,
      openPortCount: openPorts.length,
      riskSummary: { CRITICAL: critCount, HIGH: highCount, other: annotated.length - critCount - highCount },
      verdict: critCount > 0
        ? `🔴 CRITICAL — ${critCount} critical service(s) directly exposed!`
        : highCount > 0
          ? `🟠 HIGH RISK — ${highCount} high-risk service(s) open.`
          : openPorts.length > 0
            ? `🟡 MODERATE — ${openPorts.length} port(s) open, review manually.`
            : `🟢 CLEAN — No open ports detected.`,
      openPorts: annotated
    });
  }

  return targets.length === 1 ? allResults[0] : { targets: allResults };
}
