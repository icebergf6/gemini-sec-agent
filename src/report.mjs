import fs from 'fs';
import path from 'path';
import os from 'os';
import { c, stripAnsi, cols } from './ui.mjs';

// ─────────────────────────────────────────────────────────────────────────────
// REPORT FORMATTER – Unified output for ALL tools & plugins
// Supports: terminal (rich ANSI), markdown, json, table
// ─────────────────────────────────────────────────────────────────────────────

const SEVERITY_ICONS = {
  CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', INFO: 'ℹ️',
  FOUND: '✅', NOT_FOUND: '❌', RATE_LIMITED: '⚠️', UNKNOWN: '❓'
};

const SEVERITY_ANSI = {
  CRITICAL: c.bRed, HIGH: c.bYellow, MEDIUM: c.yellow, LOW: c.bCyan, INFO: c.dim,
  FOUND: c.bGreen, NOT_FOUND: c.bRed, RATE_LIMITED: c.bYellow
};

/**
 * Determine report type from plugin result data
 */
function detectReportType(data, pluginName = '') {
  if (pluginName === 'sys_ops' || data?.hardeningScore !== undefined || data?.listeningSockets !== undefined) return 'sys_ops';
  if (pluginName === 'code_patcher' || data?.backupCreated !== undefined || data?.operation !== undefined) return 'code_patch';
  if (pluginName === 'log_hunter' || data?.totalThreatsFound !== undefined) return 'log_hunt';
  if (data?.type === 'USERNAME_OSINT') return 'username';
  if (data?.type === 'PHONE_OSINT') return 'phone';
  if (data?.intelligence || data?.query) return 'info';
  if (data?.scannedManifests) return 'dependency';
  if (data?.openPorts) return 'port_scan';
  if (data?.redirectChain || data?.securityHeaders || data?.techStack) return 'web_audit';
  if (data?.findings) return 'security_audit';
  return 'generic';
}

// ─────────────────────────────────────────────────────────────────────────────
// TERMINAL (ANSI) REPORT FORMATTERS
// ─────────────────────────────────────────────────────────────────────────────

function formatUsernameTerminal(data, durationMs) {
  const lines = [];
  lines.push(`${c.bYellow}Target Query:${c.reset} @${data.query}`);
  lines.push(`${c.bYellow}Platforms Checked:${c.reset} ${data.totalPlatformsChecked}`);
  lines.push(`${c.bYellow}Profiles Found:${c.reset} ${data.foundCount > 0 ? c.bGreen + data.foundCount : c.bRed + '0'}${c.reset}`);
  lines.push(`${c.bYellow}Scan Duration:${c.reset} ${durationMs}ms`);
  lines.push('');

  if (data.foundProfiles?.length > 0) {
    lines.push(`${c.bGreen}✔ Akun Terverifikasi Ditemukan:${c.reset}`);
    lines.push(`  ${'Platform'.padEnd(16)} ${'Status'.padEnd(10)} URL`);
    lines.push(`  ${c.bBlack}${'─'.repeat(60)}${c.reset}`);
    data.foundProfiles.forEach(p => {
      lines.push(`  ${c.bold}${p.platform.padEnd(16)}${c.reset} ${c.bGreen}FOUND${c.reset}      ${c.bCyan}${p.url}${c.reset}`);
    });
  } else {
    lines.push(`  ${c.dim}Tidak ditemukan profil publik yang cocok di platform terdaftar.${c.reset}`);
  }

  // Rate-limited platforms
  if (data.rawResults) {
    const rateLimited = data.rawResults.filter(r => r.statusNote === 'RATE_LIMITED');
    if (rateLimited.length > 0) {
      lines.push('');
      lines.push(`${c.bYellow}⚠ Platform Dilindungi (Rate Limited / WAF):${c.reset}`);
      rateLimited.forEach(r => {
        lines.push(`  ${c.dim}${r.platform.padEnd(16)} HTTP ${r.statusCode}${c.reset}`);
      });
    }
  }

  if (data.dorks) {
    lines.push('');
    lines.push(`${c.bMagenta}🔗 Tautan Investigasi Lanjutan:${c.reset}`);
    lines.push(`  • Google Search:      ${c.dim}${data.dorks.google}${c.reset}`);
    lines.push(`  • Profile Aggregator: ${c.dim}${data.dorks.googleProfiles}${c.reset}`);
    lines.push(`  • WhatsMyName DB:     ${c.dim}${data.dorks.whatsMyName}${c.reset}`);
  }

  // Summary footer
  lines.push('');
  lines.push(`${c.bBlack}${'─'.repeat(50)}${c.reset}`);
  lines.push(`${c.dim}Report generated at ${new Date().toISOString()} on ${os.hostname()}${c.reset}`);

  return lines.join('\n');
}

function formatPhoneTerminal(data, durationMs) {
  const lines = [];
  lines.push(`${c.bYellow}━━━ INPUT & NORMALISASI ━━━${c.reset}`);
  lines.push(`${c.bYellow}Nomor Input:${c.reset}         ${data.query}`);
  lines.push(`${c.bYellow}Format E.164:${c.reset}        ${c.bGreen}${data.parsed.e164Format}${c.reset}`);
  lines.push(`${c.bYellow}Format Nasional:${c.reset}     ${data.parsed.nationalFormat}`);
  lines.push(`${c.bYellow}Total Digit:${c.reset}         ${data.parsed.digitsCount}`);
  lines.push(`${c.bYellow}Valid Length:${c.reset}         ${data.parsed.isValidLength ? c.bGreen + '✔ YES' : c.bRed + '✖ NO'}${c.reset}`);
  lines.push('');

  lines.push(`${c.bCyan}━━━ LOKASI & PROVIDER ━━━${c.reset}`);
  lines.push(`${c.bYellow}Negara:${c.reset}              ${data.location.flag} ${data.location.country} (${data.location.isoCode})`);
  lines.push(`${c.bYellow}Dial Prefix:${c.reset}         ${data.location.dialPrefix}`);
  lines.push(`${c.bYellow}Provider/Operator:${c.reset}   ${c.bCyan}${data.telecom.carrier}${c.reset}`);
  lines.push(`${c.bYellow}Tipe Saluran:${c.reset}        ${data.telecom.lineType}`);
  lines.push('');

  lines.push(`${c.bMagenta}━━━ OSINT QUICK ACTIONS ━━━${c.reset}`);
  lines.push(`  • WhatsApp Chat:      ${c.dim}${data.osintLinks.whatsappChat}${c.reset}`);
  lines.push(`  • Telegram Chat:      ${c.dim}${data.osintLinks.telegramChat}${c.reset}`);
  lines.push(`  • Truecaller Search:  ${c.dim}${data.osintLinks.truecallerSearch}${c.reset}`);
  lines.push(`  • Google Dork:        ${c.dim}${data.osintLinks.googleDork}${c.reset}`);
  lines.push(`  • Sync.me Database:   ${c.dim}${data.osintLinks.syncMe}${c.reset}`);

  lines.push('');
  lines.push(`${c.bBlack}${'─'.repeat(50)}${c.reset}`);
  lines.push(`${c.dim}Duration: ${durationMs}ms | Generated: ${new Date().toISOString()} | Host: ${os.hostname()}${c.reset}`);

  return lines.join('\n');
}

function formatSecurityAuditTerminal(data, pluginName, durationMs) {
  const lines = [];
  lines.push(`${c.bYellow}Target:${c.reset} ${data.target || data.targetFile || data.scannedPath || 'N/A'}`);
  lines.push(`${c.bYellow}Scan Duration:${c.reset} ${durationMs}ms`);

  if (data.verdict) {
    lines.push(`${c.bYellow}Verdict:${c.reset} ${data.verdict}`);
  }

  const summary = data.summary || data.findingsBySeverity;
  if (summary) {
    lines.push('');
    lines.push(`${c.bCyan}━━━ SEVERITY SUMMARY ━━━${c.reset}`);
    Object.entries(summary).forEach(([severity, count]) => {
      const icon = SEVERITY_ICONS[severity] || '•';
      const color = SEVERITY_ANSI[severity] || c.reset;
      lines.push(`  ${icon} ${color}${severity.padEnd(10)}${c.reset} ${count}`);
    });
  }

  const findingsList = data.findings || data.topIncidents || [];
  if (findingsList.length > 0) {
    lines.push('');
    lines.push(`${c.bYellow}━━━ FINDINGS DETAIL ━━━${c.reset}`);
    lines.push(`  ${'#'.padEnd(4)} ${'Severity'.padEnd(10)} ${'Category'.padEnd(18)} Description`);
    lines.push(`  ${c.bBlack}${'─'.repeat(70)}${c.reset}`);
    findingsList.slice(0, 30).forEach((f, i) => {
      const sev = f.severity || 'INFO';
      const color = SEVERITY_ANSI[sev] || c.reset;
      const cat = f.category || f.rule || f.type || 'GENERAL';
      const desc = f.description || f.message || f.detail || f.issue || f.reason || f.snippet || '';
      lines.push(`  ${String(i + 1).padEnd(4)} ${color}${sev.padEnd(10)}${c.reset} ${c.bCyan}${cat.padEnd(18)}${c.reset} ${desc}`);
      if (f.remediation || f.recommendation || f.fix) {
        lines.push(`  ${' '.repeat(4)} ${c.dim}→ Fix: ${f.remediation || f.recommendation || f.fix}${c.reset}`);
      }
    });
  }

  lines.push('');
  lines.push(`${c.bBlack}${'─'.repeat(50)}${c.reset}`);
  lines.push(`${c.dim}Plugin: ${pluginName} | Duration: ${durationMs}ms | ${new Date().toISOString()}${c.reset}`);

  return lines.join('\n');
}

function formatLogHuntTerminal(data, durationMs) {
  const lines = [];
  lines.push(`${c.bYellow}Total Threats:${c.reset} ${data.totalThreatsFound > 0 ? c.bRed + data.totalThreatsFound : c.bGreen + '0'}${c.reset}`);
  lines.push(`${c.bYellow}Lines Analyzed:${c.reset} ${data.linesAnalyzed || data.linesAnalysed || 'N/A'}`);
  lines.push(`${c.bYellow}Duration:${c.reset} ${durationMs}ms`);
  if (data.verdict) lines.push(`${c.bYellow}Verdict:${c.reset} ${data.verdict}`);
  lines.push('');

  if (data.findingsByCategory) {
    lines.push(`${c.bCyan}━━━ THREAT CATEGORIES ━━━${c.reset}`);
    Object.entries(data.findingsByCategory).forEach(([cat, count]) => {
      const color = count > 0 ? c.bRed : c.bGreen;
      lines.push(`  ${color}${cat.padEnd(28)}${c.reset} ${count}`);
    });
    lines.push('');
  }

  const incidents = data.findings || data.topIncidents || data.incidents || [];
  if (incidents.length > 0) {
    lines.push(`${c.bYellow}━━━ DETAILED INCIDENTS ━━━${c.reset}`);
    incidents.slice(0, 25).forEach((f, i) => {
      const sev = f.severity || 'HIGH';
      const color = SEVERITY_ANSI[sev] || c.reset;
      lines.push(`  ${color}[${i + 1}]${c.reset} ${c.bold}${f.type || f.category || 'THREAT'}${c.reset} ${color}(${sev})${c.reset}`);
      lines.push(`      ${c.dim}IP: ${f.ip || 'Unknown'} | Line: ${f.lineNum || f.line || 'N/A'}${c.reset}`);
      if (f.mitre) lines.push(`      ${c.bMagenta}MITRE: ${f.mitre}${c.reset}`);
      if (f.snippet) lines.push(`      ${c.bRed}Snippet: ${f.snippet}${c.reset}`);
      if (f.remediation) lines.push(`      ${c.dim}Fix: ${f.remediation}${c.reset}`);
    });
  }

  lines.push('');
  lines.push(`${c.bBlack}${'─'.repeat(50)}${c.reset}`);
  lines.push(`${c.dim}Generated: ${new Date().toISOString()}${c.reset}`);
  return lines.join('\n');
}

function formatPortScanTerminal(data, durationMs) {
  const lines = [];
  lines.push(`${c.bYellow}Target Host:${c.reset} ${data.target || 'N/A'}`);
  lines.push(`${c.bYellow}Duration:${c.reset} ${durationMs}ms`);
  if (data.verdict) lines.push(`${c.bYellow}Verdict:${c.reset} ${data.verdict}`);
  lines.push('');

  if (data.openPorts?.length > 0) {
    lines.push(`${c.bGreen}━━━ OPEN PORTS (${data.openPorts.length}) ━━━${c.reset}`);
    lines.push(`  ${'Port'.padEnd(8)} ${'Service'.padEnd(16)} ${'Risk'.padEnd(12)} Banner`);
    lines.push(`  ${c.bBlack}${'─'.repeat(60)}${c.reset}`);
    data.openPorts.forEach(p => {
      const riskLevel = p.risk?.level || 'CLEAN';
      const riskColor = SEVERITY_ANSI[riskLevel] || c.bGreen;
      lines.push(`  ${c.bGreen}${String(p.port).padEnd(8)}${c.reset} ${c.bCyan}${(p.service || 'unknown').padEnd(16)}${c.reset} ${riskColor}${riskLevel.padEnd(12)}${c.reset} ${c.dim}${p.banner || ''}${c.reset}`);
    });
  } else {
    lines.push(`  ${c.dim}No open ports found in scanned range.${c.reset}`);
  }

  lines.push('');
  lines.push(`${c.bBlack}${'─'.repeat(50)}${c.reset}`);
  lines.push(`${c.dim}Generated: ${new Date().toISOString()}${c.reset}`);
  return lines.join('\n');
}

function formatSysOpsTerminal(data, durationMs) {
  const lines = [];
  lines.push(`${c.bYellow}━━━ SYSTEM & PRIVILEGE POSTURE ━━━${c.reset}`);
  lines.push(`${c.bYellow}Host:${c.reset}           ${os.hostname()} (${process.platform})`);
  lines.push(`${c.bYellow}User:${c.reset}           ${data.privilege?.user || os.userInfo().username}`);
  lines.push(`${c.bYellow}Elevation:${c.reset}      ${data.privilege?.elevated ? c.bRed + '⚡ ELEVATED (Admin/Root)' : c.bGreen + 'Standard User'}${c.reset}`);
  if (data.hardeningScore !== undefined) {
    const scoreColor = data.hardeningScore >= 80 ? c.bGreen : data.hardeningScore >= 60 ? c.bYellow : c.bRed;
    lines.push(`${c.bYellow}Hardening:${c.reset}      ${scoreColor}${data.hardeningScore}/100${c.reset}`);
  }
  lines.push(`${c.bYellow}Scan Duration:${c.reset}  ${durationMs}ms`);
  lines.push('');

  if (data.listeningSockets?.length > 0) {
    lines.push(`${c.bCyan}━━━ LISTENING SOCKETS (${data.listeningSockets.length}) ━━━${c.reset}`);
    lines.push(`  ${'Proto'.padEnd(8)} ${'Port'.padEnd(8)} ${'Local Address'.padEnd(24)} PID`);
    lines.push(`  ${c.bBlack}${'─'.repeat(50)}${c.reset}`);
    data.listeningSockets.slice(0, 15).forEach(s => {
      lines.push(`  ${c.bGreen}${(s.proto || 'TCP').padEnd(8)}${c.reset} ${c.bYellow}${String(s.port || '-').padEnd(8)}${c.reset} ${(s.localAddress || s.raw || '-').padEnd(24)} ${s.pid || '-'}`);
    });
    lines.push('');
  }

  lines.push(`${c.bBlack}${'─'.repeat(50)}${c.reset}`);
  lines.push(`${c.dim}Generated: ${new Date().toISOString()}${c.reset}`);
  return lines.join('\n');
}

function formatCodePatchTerminal(data, durationMs) {
  const lines = [];
  lines.push(`${c.bYellow}Target File:${c.reset}    ${data.targetFile || 'N/A'}`);
  lines.push(`${c.bYellow}Operation:${c.reset}      ${data.operation || 'patch'}`);
  if (data.backupCreated) {
    lines.push(`${c.bYellow}Backup Created:${c.reset} ${c.bCyan}${data.backupCreated}${c.reset}`);
  }
  if (data.changedLines !== undefined) {
    lines.push(`${c.bYellow}Changed Lines:${c.reset}  ${c.bGreen}${data.changedLines}${c.reset}`);
  }
  lines.push(`${c.bYellow}Duration:${c.reset}       ${durationMs}ms`);
  lines.push('');

  if (data.diffPreview) {
    lines.push(`${c.bCyan}━━━ DIFF PREVIEW ━━━${c.reset}`);
    lines.push(data.diffPreview);
    lines.push('');
  }

  if (data.message) {
    lines.push(`${c.bGreen}${data.message}${c.reset}`);
  }

  lines.push('');
  lines.push(`${c.bBlack}${'─'.repeat(50)}${c.reset}`);
  lines.push(`${c.dim}Generated: ${new Date().toISOString()}${c.reset}`);
  return lines.join('\n');
}

function formatGenericTerminal(data, pluginName, durationMs) {
  const json = JSON.stringify(data, null, 2);
  const lines = [];
  lines.push(`${c.bYellow}Plugin:${c.reset} ${pluginName}`);
  lines.push(`${c.bYellow}Duration:${c.reset} ${durationMs}ms`);
  lines.push('');
  lines.push(json);
  lines.push('');
  lines.push(`${c.bBlack}${'─'.repeat(50)}${c.reset}`);
  lines.push(`${c.dim}Generated: ${new Date().toISOString()} | Host: ${os.hostname()}${c.reset}`);
  return lines.join('\n');
}

/**
 * Format result for terminal display (rich ANSI output)
 */
export function formatTerminal(data, { pluginName = 'unknown', durationMs = 0 } = {}) {
  const type = detectReportType(data, pluginName);
  switch (type) {
    case 'username':    return formatUsernameTerminal(data, durationMs);
    case 'phone':       return formatPhoneTerminal(data, durationMs);
    case 'log_hunt':    return formatLogHuntTerminal(data, durationMs);
    case 'port_scan':   return formatPortScanTerminal(data, durationMs);
    case 'sys_ops':     return formatSysOpsTerminal(data, durationMs);
    case 'code_patch':  return formatCodePatchTerminal(data, durationMs);
    case 'security_audit':
    case 'web_audit':
    case 'dependency':
      return formatSecurityAuditTerminal(data, pluginName, durationMs);
    default:
      return formatGenericTerminal(data, pluginName, durationMs);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MARKDOWN REPORT FORMATTER
// ─────────────────────────────────────────────────────────────────────────────

function formatUsernameMarkdown(data, durationMs) {
  const lines = [];
  lines.push(`# 👤 OSINT Username Footprint Report`);
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| **Target** | \`@${data.query}\` |`);
  lines.push(`| **Platforms Checked** | ${data.totalPlatformsChecked} |`);
  lines.push(`| **Profiles Found** | ${data.foundCount} |`);
  lines.push(`| **Scan Duration** | ${durationMs}ms |`);
  lines.push(`| **Timestamp** | ${data.timestamp || new Date().toISOString()} |`);
  lines.push('');

  if (data.foundProfiles?.length > 0) {
    lines.push(`## ✅ Verified Profiles`);
    lines.push('');
    lines.push(`| # | Platform | URL |`);
    lines.push(`|---|----------|-----|`);
    data.foundProfiles.forEach((p, i) => {
      lines.push(`| ${i + 1} | **${p.platform}** | [${p.url}](${p.url}) |`);
    });
    lines.push('');
  }

  if (data.rawResults) {
    const rateLimited = data.rawResults.filter(r => r.statusNote === 'RATE_LIMITED');
    const notFound = data.rawResults.filter(r => r.statusNote === 'NOT_FOUND');
    if (rateLimited.length > 0) {
      lines.push(`## ⚠️ Rate Limited / Protected`);
      lines.push('');
      lines.push(`| Platform | HTTP Status |`);
      lines.push(`|----------|-------------|`);
      rateLimited.forEach(r => {
        lines.push(`| ${r.platform} | ${r.statusCode} |`);
      });
      lines.push('');
    }
    lines.push(`## ❌ Not Found (${notFound.length} platforms)`);
    lines.push('');
    lines.push(`<details><summary>Click to expand</summary>\n`);
    notFound.forEach(r => {
      lines.push(`- ${r.platform} (HTTP ${r.statusCode})`);
    });
    lines.push(`\n</details>`);
    lines.push('');
  }

  if (data.dorks) {
    lines.push(`## 🔗 Investigation Links`);
    lines.push('');
    lines.push(`- [Google Search](${data.dorks.google})`);
    lines.push(`- [Profile Aggregator](${data.dorks.googleProfiles})`);
    lines.push(`- [WhatsMyName](${data.dorks.whatsMyName})`);
    lines.push('');
  }

  lines.push(`---`);
  lines.push(`*Generated by AGY Gemini Sec Agent on ${os.hostname()} at ${new Date().toISOString()}*`);

  return lines.join('\n');
}

function formatPhoneMarkdown(data, durationMs) {
  const lines = [];
  lines.push(`# 📞 OSINT Phone & Telecom Intelligence Report`);
  lines.push('');
  lines.push(`| Field | Normalized Value |`);
  lines.push(`|-------|------------------|`);
  lines.push(`| **Query Input** | \`${data.query}\` |`);
  lines.push(`| **E.164 Format** | \`${data.parsed.e164Format}\` |`);
  lines.push(`| **National Format** | \`${data.parsed.nationalFormat}\` |`);
  lines.push(`| **Digits Count** | ${data.parsed.digitsCount} |`);
  lines.push(`| **Country** | ${data.location.flag} ${data.location.country} (${data.location.isoCode}) |`);
  lines.push(`| **Dial Prefix** | \`${data.location.dialPrefix}\` |`);
  lines.push(`| **Carrier** | ${data.telecom.carrier} |`);
  lines.push(`| **Line Type** | ${data.telecom.lineType} |`);
  lines.push('');

  lines.push(`## 🔗 OSINT Quick Actions`);
  lines.push('');
  lines.push(`| Service | Link |`);
  lines.push(`|---------|------|`);
  lines.push(`| WhatsApp | [Open Chat](${data.osintLinks.whatsappChat}) |`);
  lines.push(`| Telegram | [Open Chat](${data.osintLinks.telegramChat}) |`);
  lines.push(`| Truecaller | [Search](${data.osintLinks.truecallerSearch}) |`);
  lines.push(`| Google Dork | [Search](${data.osintLinks.googleDork}) |`);
  lines.push(`| Sync.me | [Lookup](${data.osintLinks.syncMe}) |`);
  lines.push('');

  lines.push(`---`);
  lines.push(`*Duration: ${durationMs}ms | Generated by AGY on ${os.hostname()} at ${new Date().toISOString()}*`);

  return lines.join('\n');
}

function formatSecurityAuditMarkdown(data, pluginName, durationMs) {
  const lines = [];
  lines.push(`# 🛡️ Security Audit Report — ${pluginName}`);
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| **Target** | \`${data.target || data.targetFile || data.scannedPath || 'N/A'}\` |`);
  lines.push(`| **Plugin** | ${pluginName} |`);
  lines.push(`| **Duration** | ${durationMs}ms |`);
  lines.push(`| **Timestamp** | ${new Date().toISOString()} |`);
  if (data.verdict) {
    lines.push(`| **Verdict** | ${data.verdict} |`);
  }
  lines.push('');

  const summary = data.summary || data.findingsBySeverity;
  if (summary) {
    lines.push(`## Severity Summary`);
    lines.push('');
    lines.push(`| Severity | Count |`);
    lines.push(`|----------|-------|`);
    Object.entries(summary).forEach(([sev, count]) => {
      const icon = SEVERITY_ICONS[sev] || '';
      lines.push(`| ${icon} ${sev} | **${count}** |`);
    });
    lines.push('');
  }

  const findingsList = data.findings || data.topIncidents || [];
  if (findingsList.length > 0) {
    lines.push(`## Findings Detail`);
    lines.push('');
    lines.push(`| # | Severity | Category | Description | Remediation |`);
    lines.push(`|---|----------|----------|-------------|-------------|`);
    findingsList.forEach((f, i) => {
      const sev = f.severity || 'INFO';
      const cat = f.category || f.rule || f.type || 'GENERAL';
      const desc = (f.description || f.message || f.detail || f.issue || f.reason || f.snippet || '').replace(/\|/g, '\\|');
      const fix = (f.remediation || f.recommendation || f.fix || '-').replace(/\|/g, '\\|');
      lines.push(`| ${i + 1} | ${SEVERITY_ICONS[sev] || ''} ${sev} | ${cat} | ${desc} | ${fix} |`);
    });
    lines.push('');
  }

  lines.push(`---`);
  lines.push(`*Generated by AGY Gemini Sec Agent on ${os.hostname()}*`);

  return lines.join('\n');
}

function formatSysOpsMarkdown(data, durationMs) {
  const lines = [];
  lines.push(`# 🖥️ System Posture Audit Report`);
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| **Hostname** | \`${os.hostname()}\` |`);
  lines.push(`| **Platform** | \`${process.platform}\` |`);
  lines.push(`| **User** | \`${data.privilege?.user || os.userInfo().username}\` |`);
  lines.push(`| **Elevation** | ${data.privilege?.elevated ? '⚡ Elevated (Admin/Root)' : 'Standard User'} |`);
  if (data.hardeningScore !== undefined) {
    lines.push(`| **Hardening Score** | **${data.hardeningScore}/100** |`);
  }
  lines.push(`| **Duration** | ${durationMs}ms |`);
  lines.push('');

  if (data.listeningSockets?.length > 0) {
    lines.push(`## 📡 Listening Sockets`);
    lines.push('');
    lines.push(`| Proto | Port | Local Address | PID |`);
    lines.push(`|-------|------|---------------|-----|`);
    data.listeningSockets.forEach(s => {
      lines.push(`| ${s.proto || 'TCP'} | **${s.port || '-'}** | \`${s.localAddress || s.raw || '-'}\` | ${s.pid || '-'} |`);
    });
    lines.push('');
  }

  lines.push(`---`);
  lines.push(`*Generated by AGY Gemini Sec Agent on ${os.hostname()}*`);
  return lines.join('\n');
}

function formatCodePatchMarkdown(data, durationMs) {
  const lines = [];
  lines.push(`# 🛠️ Code Patch Execution Report`);
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| **Target File** | \`${data.targetFile || 'N/A'}\` |`);
  lines.push(`| **Operation** | \`${data.operation || 'patch'}\` |`);
  if (data.backupCreated) {
    lines.push(`| **Backup File** | \`${data.backupCreated}\` |`);
  }
  if (data.changedLines !== undefined) {
    lines.push(`| **Changed Lines** | ${data.changedLines} |`);
  }
  lines.push(`| **Duration** | ${durationMs}ms |`);
  lines.push('');

  if (data.diffPreview) {
    lines.push('## Diff Preview');
    lines.push('');
    lines.push('```diff');
    lines.push(data.diffPreview);
    lines.push('```');
    lines.push('');
  }

  lines.push(`---`);
  lines.push(`*Generated by AGY Gemini Sec Agent on ${os.hostname()}*`);
  return lines.join('\n');
}

function formatGenericMarkdown(data, pluginName, durationMs) {
  const lines = [];
  lines.push(`# 📋 Plugin Execution Report — ${pluginName}`);
  lines.push('');
  lines.push(`- **Plugin:** ${pluginName}`);
  lines.push(`- **Duration:** ${durationMs}ms`);
  lines.push(`- **Timestamp:** ${new Date().toISOString()}`);
  lines.push('');
  lines.push('## Raw Output');
  lines.push('');
  lines.push('```json');
  lines.push(JSON.stringify(data, null, 2));
  lines.push('```');
  lines.push('');
  lines.push(`---`);
  lines.push(`*Generated by AGY Gemini Sec Agent on ${os.hostname()}*`);

  return lines.join('\n');
}

/**
 * Format result as a clean Markdown report
 */
export function formatMarkdown(data, { pluginName = 'unknown', durationMs = 0 } = {}) {
  const type = detectReportType(data, pluginName);
  switch (type) {
    case 'username':    return formatUsernameMarkdown(data, durationMs);
    case 'phone':       return formatPhoneMarkdown(data, durationMs);
    case 'sys_ops':     return formatSysOpsMarkdown(data, durationMs);
    case 'code_patch':  return formatCodePatchMarkdown(data, durationMs);
    case 'security_audit':
    case 'web_audit':
    case 'dependency':
    case 'log_hunt':
      return formatSecurityAuditMarkdown(data, pluginName, durationMs);
    default:
      return formatGenericMarkdown(data, pluginName, durationMs);
  }
}

/**
 * Format result as a JSON string (machine-readable)
 */
export function formatJSON(data, { pluginName = 'unknown', durationMs = 0 } = {}) {
  return JSON.stringify({
    report: {
      generator: 'AGY Gemini Sec Agent',
      version: '2.0.0',
      host: os.hostname(),
      timestamp: new Date().toISOString(),
      plugin: pluginName,
      durationMs
    },
    data
  }, null, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// REPORT FILE WRITER
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Ensure reports directory exists and write report to file
 * @returns {string} Path to the written report file
 */
export function writeReport(content, { format = 'md', pluginName = 'report', dir = null } = {}) {
  const reportsDir = dir || path.join(process.cwd(), 'reports');
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }

  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const ext = format === 'json' ? 'json' : 'md';
  const filename = `${pluginName}-${ts}.${ext}`;
  const filePath = path.join(reportsDir, filename);

  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

/**
 * Main report entry point – format + optionally write to file
 */
export function generateReport(data, { pluginName = 'unknown', durationMs = 0, format = 'terminal', save = false, dir = null } = {}) {
  let content;
  switch (format) {
    case 'json':
      content = formatJSON(data, { pluginName, durationMs });
      break;
    case 'markdown':
    case 'md':
      content = formatMarkdown(data, { pluginName, durationMs });
      break;
    case 'terminal':
    default:
      content = formatTerminal(data, { pluginName, durationMs });
      break;
  }

  let filePath = null;
  if (save) {
    const saveFormat = (format === 'terminal') ? 'md' : format;
    const saveContent = (format === 'terminal')
      ? formatMarkdown(data, { pluginName, durationMs })
      : content;
    filePath = writeReport(saveContent, { format: saveFormat, pluginName, dir });
  }

  return { content, filePath };
}
