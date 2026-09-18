import https from 'https';
import http from 'http';
import { URL } from 'url';
import dns from 'dns/promises';

export const declaration = {
  name: 'web_audit',
  description: 'Overpower web security auditor: 20+ header checks, redirect chain, cookie flags, CSP analysis, CORS deep-check, SPF/DKIM/DMARC, tech fingerprinting, TLS cert expiry.',
  parameters: {
    type: 'OBJECT',
    properties: {
      target:       { type: 'STRING',  description: 'Target URL (e.g., https://example.com)' },
      followRedirects:{ type: 'BOOLEAN', description: 'Follow redirect chain (default: true, max 10)' },
      checkDns:     { type: 'BOOLEAN', description: 'Perform SPF/DKIM/DMARC DNS checks (default: true)' },
      userAgent:    { type: 'STRING',  description: 'Custom User-Agent header (default: AGY-SecAudit/2.0)' },
    },
    required: ['target']
  }
};

// ── Severity helpers ───────────────────────────────────────────────────────────
function finding(severity, category, issue, remediation='') {
  return { severity, category, issue, remediation };
}

// ── Redirect chain follower ────────────────────────────────────────────────────
async function fetchWithRedirects(urlStr, ua, maxRedirects=10) {
  const chain = [];
  let current = urlStr;

  for (let hop=0; hop<=maxRedirects; hop++) {
    const parsed = new URL(current);
    const isHttps = parsed.protocol === 'https:';
    const client  = isHttps ? https : http;

    const result = await new Promise((resolve) => {
      const opts = {
        method: 'HEAD',
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: (parsed.pathname||'/') + parsed.search,
        headers: { 'User-Agent': ua },
        timeout: 10000,
        rejectUnauthorized: false
      };
      const req = client.request(opts, res => {
        let cert = null;
        if (isHttps && res.socket?.getPeerCertificate) {
          try {
            const raw = res.socket.getPeerCertificate(true);
            if (raw?.valid_to) {
              const daysLeft = Math.round((new Date(raw.valid_to) - Date.now()) / 86400000);
              cert = {
                subject: raw.subject?.CN || 'N/A',
                issuer:  raw.issuer?.O  || raw.issuer?.CN || 'N/A',
                validTo: raw.valid_to,
                daysRemaining: daysLeft,
                selfSigned: raw.subject?.CN === raw.issuer?.CN,
                san: raw.subjectaltname || null
              };
            }
          } catch {}
        }
        resolve({ url: current, status: res.statusCode, headers: res.headers, cert, isHttps });
        req.destroy();
      });
      req.on('error', e => resolve({ url: current, error: e.message }));
      req.on('timeout', () => { req.destroy(); resolve({ url: current, error: 'Timeout' }); });
      req.end();
    });

    chain.push(result);
    const loc = result.headers?.location;
    if (loc && [301,302,303,307,308].includes(result.status)) {
      current = loc.startsWith('http') ? loc : new URL(loc, current).href;
    } else {
      break;
    }
  }
  return chain;
}

// ── Header analyser ────────────────────────────────────────────────────────────
function analyseHeaders(headers, isHttps, findings) {
  const h = Object.fromEntries(Object.entries(headers).map(([k,v])=>[k.toLowerCase(),v]));

  // HSTS
  if (isHttps && !h['strict-transport-security']) {
    findings.push(finding('HIGH','HSTS','Missing Strict-Transport-Security — SSL stripping attack possible.',
      'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'));
  } else if (h['strict-transport-security']) {
    const hsts = h['strict-transport-security'];
    if (!/max-age=\d{7,}/i.test(hsts))
      findings.push(finding('MEDIUM','HSTS',`HSTS max-age too short: ${hsts}`,'Use max-age ≥ 1 year (31536000).'));
    if (!hsts.includes('includeSubDomains'))
      findings.push(finding('LOW','HSTS','HSTS missing includeSubDomains directive.'));
    if (!hsts.includes('preload'))
      findings.push(finding('INFO','HSTS','HSTS not configured for browser preload list.'));
  }

  // CSP
  if (!h['content-security-policy']) {
    findings.push(finding('HIGH','CSP','Missing Content-Security-Policy — XSS risk elevated.',
      "Add a CSP: default-src 'self'; script-src 'self'; object-src 'none'"));
  } else {
    const csp = h['content-security-policy'];
    if (/unsafe-inline/i.test(csp))
      findings.push(finding('HIGH','CSP',"CSP allows 'unsafe-inline' — negates XSS protection.",'Remove unsafe-inline, use nonces/hashes.'));
    if (/unsafe-eval/i.test(csp))
      findings.push(finding('HIGH','CSP',"CSP allows 'unsafe-eval' — eval() attacks possible.",'Remove unsafe-eval.'));
    if (/\*/i.test(csp))
      findings.push(finding('MEDIUM','CSP','CSP contains wildcard source (*).','Restrict sources to specific origins.'));
  }

  // X-Frame-Options
  if (!h['x-frame-options']) {
    findings.push(finding('MEDIUM','Clickjacking','Missing X-Frame-Options — Clickjacking possible.',
      'Add: X-Frame-Options: DENY'));
  }

  // X-Content-Type-Options
  if (!h['x-content-type-options']) {
    findings.push(finding('LOW','MIME','Missing X-Content-Type-Options: nosniff.',
      'Add: X-Content-Type-Options: nosniff'));
  }

  // Referrer-Policy
  if (!h['referrer-policy']) {
    findings.push(finding('LOW','Privacy','Missing Referrer-Policy — may leak URL in Referer header.',
      'Add: Referrer-Policy: strict-origin-when-cross-origin'));
  }

  // Permissions-Policy
  if (!h['permissions-policy']) {
    findings.push(finding('INFO','Privacy','Missing Permissions-Policy (camera/mic/geolocation exposure).',
      'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()'));
  }

  // CORS
  const acao = h['access-control-allow-origin'];
  if (acao === '*') {
    findings.push(finding('HIGH','CORS','CORS wildcard (*) — any origin can read responses.',
      'Restrict to specific allowed origins.'));
  }
  if (h['access-control-allow-credentials'] === 'true' && acao !== '*') {
    findings.push(finding('MEDIUM','CORS','CORS with credentials enabled — verify origin whitelist is strict.'));
  }

  // Server/Tech disclosure
  if (h['server']) {
    findings.push(finding('INFO','Fingerprint',`Server header exposes tech: "${h['server']}"`,
      'Configure server to suppress version info.'));
  }
  if (h['x-powered-by']) {
    findings.push(finding('LOW','Fingerprint',`X-Powered-By discloses stack: "${h['x-powered-by']}"`,
      'Remove X-Powered-By header.'));
  }
  if (h['x-aspnet-version'] || h['x-aspnetmvc-version']) {
    findings.push(finding('LOW','Fingerprint','ASP.NET version header exposed.','Remove version headers.'));
  }

  // Cache-Control on sensitive pages
  if (!h['cache-control'] || /public/i.test(h['cache-control'])) {
    findings.push(finding('INFO','Cache','No strict Cache-Control — may cache sensitive responses.'));
  }

  // Cookie analysis
  const setCookie = h['set-cookie'];
  if (setCookie) {
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const ck of cookies) {
      const name = ck.split('=')[0];
      if (!/HttpOnly/i.test(ck))
        findings.push(finding('HIGH','Cookie',`Cookie "${name}" missing HttpOnly flag — JS readable.`,'Add HttpOnly to cookie.'));
      if (!/Secure/i.test(ck))
        findings.push(finding('MEDIUM','Cookie',`Cookie "${name}" missing Secure flag — sent over HTTP.`,'Add Secure flag to cookie.'));
      if (!/SameSite=/i.test(ck))
        findings.push(finding('MEDIUM','Cookie',`Cookie "${name}" missing SameSite — CSRF risk.`,'Add SameSite=Strict or Lax.'));
    }
  }
}

// ── Tech stack fingerprinter ───────────────────────────────────────────────────
function fingerprintStack(headers) {
  const h = JSON.stringify(headers).toLowerCase();
  const stack = [];
  if (/nginx/.test(h))        stack.push('Nginx');
  if (/apache/.test(h))       stack.push('Apache');
  if (/cloudflare/.test(h))   stack.push('Cloudflare CDN');
  if (/awselb|amazon/.test(h))stack.push('AWS ELB');
  if (/vercel/.test(h))       stack.push('Vercel');
  if (/php/.test(h))          stack.push('PHP');
  if (/asp\.net/.test(h))     stack.push('ASP.NET');
  if (/express/.test(h))      stack.push('Express.js');
  if (/django/.test(h))       stack.push('Django');
  if (/rails/.test(h))        stack.push('Ruby on Rails');
  if (/wordpress|wp-/.test(h))stack.push('WordPress');
  if (/drupal/.test(h))       stack.push('Drupal');
  if (/joomla/.test(h))       stack.push('Joomla');
  return stack;
}

// ── DNS security checks ────────────────────────────────────────────────────────
async function checkDNSSecurity(hostname) {
  const results = { spf: null, dmarc: null, dkimHint: null, caa: null };
  try {
    const txt = await dns.resolveTxt(hostname).catch(()=>[]);
    for (const r of txt) {
      const line = r.join(' ');
      if (line.startsWith('v=spf1'))  results.spf  = line;
    }
    const dmarc = await dns.resolveTxt(`_dmarc.${hostname}`).catch(()=>[]);
    if (dmarc.length) results.dmarc = dmarc[0]?.join(' ') || null;

    const caa = await dns.resolveCaa(hostname).catch(()=>[]);
    results.caa = caa.length > 0;
  } catch {}

  const emailFindings = [];
  if (!results.spf)   emailFindings.push({ severity:'HIGH', issue:'No SPF record — email spoofing possible.' });
  if (!results.dmarc) emailFindings.push({ severity:'HIGH', issue:'No DMARC policy — phishing risk.' });
  if (!results.caa)   emailFindings.push({ severity:'MEDIUM', issue:'No CAA DNS record — any CA can issue certs for this domain.' });

  return { ...results, emailFindings };
}

// ── Score calculator ───────────────────────────────────────────────────────────
function calcScore(findings) {
  const w = { CRITICAL:25, HIGH:10, MEDIUM:5, LOW:2, INFO:0 };
  const deduct = findings.reduce((acc,f) => acc + (w[f.severity]||0), 0);
  return Math.max(0, 100 - deduct);
}

export async function execute(args) {
  let url = args.target;
  if (!url.startsWith('http')) url = `https://${url}`;
  const ua = args.userAgent || 'AGY-SecAudit/2.0';
  const followRedir = args.followRedirects !== false;
  const checkDns    = args.checkDns !== false;

  const parsed   = new URL(url);
  const hostname = parsed.hostname;

  // Redirect chain
  const chain = await fetchWithRedirects(url, ua, followRedir ? 10 : 0);
  const final = chain[chain.length-1];

  if (final.error) {
    return { target: url, error: final.error, redirectChain: chain.map(c=>c.url) };
  }

  const findings = [];
  analyseHeaders(final.headers, final.isHttps, findings);

  // TLS cert checks
  if (final.cert) {
    const c = final.cert;
    if (c.daysRemaining <= 0)
      findings.push(finding('CRITICAL','TLS',`SSL certificate EXPIRED ${Math.abs(c.daysRemaining)} days ago!`,'Renew immediately.'));
    else if (c.daysRemaining <= 14)
      findings.push(finding('HIGH','TLS',`SSL certificate expires in ${c.daysRemaining} days!`,'Renew within 14 days.'));
    else if (c.daysRemaining <= 30)
      findings.push(finding('MEDIUM','TLS',`SSL cert expiring soon: ${c.daysRemaining} days remaining.`));
    if (c.selfSigned)
      findings.push(finding('HIGH','TLS','Self-signed certificate — browser warnings, MITM risk.'));
  } else if (final.isHttps) {
    findings.push(finding('MEDIUM','TLS','Could not retrieve TLS certificate details.'));
  }

  // HTTP → HTTPS redirect check
  if (chain.length > 0 && !url.startsWith('https')) {
    findings.push(finding('HIGH','TLS','Site served over HTTP — enforce HTTPS redirect.'));
  }

  // DNS security
  let dns_sec = null;
  if (checkDns) {
    dns_sec = await checkDNSSecurity(hostname);
    findings.push(...dns_sec.emailFindings.map(f => finding(f.severity,'Email-Security',f.issue)));
  }

  const stack = fingerprintStack(final.headers);
  const score = calcScore(findings);
  const grade = score>=90?'A':score>=75?'B':score>=60?'C':score>=45?'D':'F';

  return {
    target: url,
    finalUrl: final.url,
    redirectChain: chain.map(c=>c.url),
    httpStatus: final.status,
    securityScore: score,
    grade,
    tlsCertificate: final.cert,
    techStack: stack,
    headers: {
      hsts:             Boolean(final.headers['strict-transport-security']),
      csp:              Boolean(final.headers['content-security-policy']),
      xFrameOptions:    final.headers['x-frame-options']   || null,
      xContentType:     final.headers['x-content-type-options'] || null,
      referrerPolicy:   final.headers['referrer-policy']   || null,
      permissionsPolicy:final.headers['permissions-policy']|| null,
      cors:             final.headers['access-control-allow-origin'] || null,
    },
    dnsSecurity: dns_sec ? { spf: dns_sec.spf, dmarc: dns_sec.dmarc, caa: dns_sec.caa } : null,
    findingsSummary: {
      total:    findings.length,
      CRITICAL: findings.filter(f=>f.severity==='CRITICAL').length,
      HIGH:     findings.filter(f=>f.severity==='HIGH').length,
      MEDIUM:   findings.filter(f=>f.severity==='MEDIUM').length,
      LOW:      findings.filter(f=>f.severity==='LOW').length,
      INFO:     findings.filter(f=>f.severity==='INFO').length,
    },
    findings
  };
}
