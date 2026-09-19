import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { generateReport, formatTerminal, formatMarkdown, formatJSON, writeReport } from '../src/report.mjs';
import { sanitizeInput, isPhoneLike, maskSensitive, timestampSlug } from '../src/utils.mjs';

test('1. sanitizeInput removes control characters and strips dangerous shell characters', () => {
  const dirty = 'echo "hello" ; rm -rf / \x00\x1b[31m';
  const clean = sanitizeInput(dirty);
  assert.ok(!clean.includes('\x00'));
  assert.ok(!clean.includes('\x1b'));
  assert.ok(!clean.includes(';'));
  assert.ok(!clean.includes('`'));
});

test('2. isPhoneLike correctly classifies phone numbers vs usernames', () => {
  assert.equal(isPhoneLike('+628123456789'), true);
  assert.equal(isPhoneLike('0812-3456-7890'), true);
  assert.equal(isPhoneLike('62812345678'), true);
  assert.equal(isPhoneLike('+1-555-123-4567'), true);
  assert.equal(isPhoneLike('octocat'), false);
  assert.equal(isPhoneLike('john_doe_99'), false);
  assert.equal(isPhoneLike('security-expert'), false);
});

test('3. maskSensitive masks long credentials and API keys', () => {
  const key = 'AIzaSyD1234567890abcdefg';
  const masked = maskSensitive(key);
  assert.ok(masked.startsWith('AIzaS'));
  assert.ok(masked.endsWith('efg'));
  assert.ok(masked.includes('•'));
});

test('4. formatTerminal renders clean styled output for username OSINT', () => {
  const data = {
    type: 'USERNAME_OSINT',
    query: 'octocat',
    totalPlatformsChecked: 10,
    foundCount: 1,
    foundProfiles: [
      { platform: 'GitHub', url: 'https://github.com/octocat', status: 'FOUND' }
    ]
  };
  const terminalOut = formatTerminal(data, { pluginName: 'osint_search', durationMs: 120 });
  assert.ok(terminalOut.includes('@octocat'));
  assert.ok(terminalOut.includes('GitHub'));
  assert.ok(terminalOut.includes('Platforms Checked'));
});

test('5. formatMarkdown creates valid Markdown document with metadata and tables', () => {
  const data = {
    type: 'USERNAME_OSINT',
    query: 'octocat',
    totalPlatformsChecked: 10,
    foundCount: 1,
    foundProfiles: [
      { platform: 'GitHub', url: 'https://github.com/octocat', status: 'FOUND' }
    ]
  };
  const md = formatMarkdown(data, { pluginName: 'osint_search', durationMs: 120 });
  assert.ok(md.includes('# 👤 OSINT Username Footprint Report'));
  assert.ok(md.includes('| **Target** | `@octocat` |'));
  assert.ok(md.includes('Verified Profiles'));
});

test('6. formatJSON returns parseable valid JSON matching schema', () => {
  const data = {
    findings: [{ rule: 'NO_ROOT', severity: 'HIGH' }]
  };
  const jsonStr = formatJSON(data, { pluginName: 'iac_linter', durationMs: 45 });
  const parsed = JSON.parse(jsonStr);
  assert.equal(parsed.report.generator, 'AGY Gemini Sec Agent');
  assert.equal(parsed.report.plugin, 'iac_linter');
  assert.equal(parsed.report.version, '2.0.0');
  assert.equal(parsed.data.findings.length, 1);
});

test('7. writeReport persists reports to disk safely', () => {
  const sampleMd = '# Test Report\n\nAll systems operational.';
  const outPath = writeReport(sampleMd, { format: 'md', pluginName: 'unit_test' });
  assert.ok(fs.existsSync(outPath));
  const content = fs.readFileSync(outPath, 'utf8');
  assert.ok(content.includes('Test Report'));
  // Clean up test report file
  try {
    fs.unlinkSync(outPath);
  } catch {}
});

test('8. generateReport formats and optionally saves reports', () => {
  const data = {
    type: 'PHONE_OSINT',
    query: '+628123456789',
    parsed: {
      e164Format: '+628123456789',
      nationalFormat: '0812-3456-789',
      digitsCount: 12,
      isValidLength: true
    },
    location: {
      flag: '🇮🇩',
      country: 'Indonesia',
      isoCode: 'ID',
      dialPrefix: '+62'
    },
    telecom: {
      carrier: 'Telkomsel',
      lineType: 'Mobile'
    },
    osintLinks: {
      whatsappChat: 'https://wa.me/628123456789',
      telegramChat: 'https://t.me/+628123456789',
      truecallerSearch: 'https://www.truecaller.com/search/id/+628123456789',
      googleDork: 'https://google.com/search?q=%22%2B628123456789%22',
      syncMe: 'https://sync.me/search/?number=%2B628123456789'
    }
  };

  // Test terminal formatting without save
  const res = generateReport(data, { pluginName: 'osint_search', format: 'terminal', save: false });
  assert.ok(res.content.includes('+628123456789'));
  assert.equal(res.filePath, null);

  // Test save to file
  const savedRes = generateReport(data, { pluginName: 'osint_phone_test', format: 'md', save: true });
  assert.ok(savedRes.filePath);
  assert.ok(fs.existsSync(savedRes.filePath));
  // Clean up
  try {
    fs.unlinkSync(savedRes.filePath);
  } catch {}
});

test('9. formatSysOps formats posture score and listening sockets', () => {
  const sysData = {
    privilege: { elevated: false, user: 'testuser' },
    hardeningScore: 85,
    listeningSockets: [
      { proto: 'TCP', port: 8080, localAddress: '127.0.0.1:8080', pid: '1234' }
    ]
  };
  const termOut = formatTerminal(sysData, { pluginName: 'sys_ops', durationMs: 50 });
  assert.ok(termOut.includes('SYSTEM & PRIVILEGE POSTURE'));
  assert.ok(termOut.includes('85/100'));
  assert.ok(termOut.includes('8080'));

  const mdOut = formatMarkdown(sysData, { pluginName: 'sys_ops', durationMs: 50 });
  assert.ok(mdOut.includes('# 🖥️ System Posture Audit Report'));
  assert.ok(mdOut.includes('85/100'));
  assert.ok(mdOut.includes('8080'));
});

test('10. formatLogHunt correctly formats threat counts and incident lists', () => {
  const logData = {
    linesAnalyzed: 500,
    totalThreatsFound: 2,
    findingsByCategory: { SQL_INJECTION: 2 },
    findings: [
      { ip: '1.2.3.4', type: 'SQL_INJECTION', severity: 'HIGH', lineNum: 10, snippet: 'SELECT * FROM users WHERE id=1 OR 1=1' }
    ]
  };
  const termOut = formatTerminal(logData, { pluginName: 'log_hunter', durationMs: 80 });
  assert.ok(termOut.includes('Total Threats:'));
  assert.ok(termOut.includes('SQL_INJECTION'));
  assert.ok(termOut.includes('1.2.3.4'));
});

test('11. formatCodePatch correctly formats diffs and backup info', () => {
  const patchData = {
    targetFile: 'src/app.js',
    operation: 'replace',
    backupCreated: 'src/app.js.20260919.bak',
    changedLines: 1,
    diffPreview: '- const x = 1;\n+ const x = 2;',
    message: 'Patch applied successfully'
  };
  const termOut = formatTerminal(patchData, { pluginName: 'code_patcher', durationMs: 30 });
  assert.ok(termOut.includes('src/app.js'));
  assert.ok(termOut.includes('DIFF PREVIEW'));

  const mdOut = formatMarkdown(patchData, { pluginName: 'code_patcher', durationMs: 30 });
  assert.ok(mdOut.includes('# 🛠️ Code Patch Execution Report'));
  assert.ok(mdOut.includes('src/app.js.20260919.bak'));
});
