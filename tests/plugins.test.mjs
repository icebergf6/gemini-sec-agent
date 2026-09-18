import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'path';
import fs from 'fs/promises';

import { pluginLoader } from '../src/plugin_loader.mjs';
import { keyManager } from '../src/config.mjs';

test('1. PluginLoader loads all 9 plugins', async () => {
  const plugins = await pluginLoader.loadPlugins();
  assert.equal(plugins.length, 9, 'Harus memuat tepat 9 plugin cybersecurity & DevSecOps');

  const names = plugins.map(p => p.name).sort();
  const expected = [
    'code_patcher',
    'dep_audit',
    'iac_linter',
    'log_hunter',
    'osint_search',
    'port_scanner',
    'secret_scanner',
    'sys_ops',
    'web_audit'
  ].sort();
  assert.deepEqual(names, expected);
});

test('2. KeyManager loads keys and masks them properly', () => {
  keyManager.addKey('AIzaSyDummyTestKeyForUnitTestingPurposes12345');
  const masked = keyManager.getMaskedKeys();
  assert.ok(masked.length > 0);
  const activeKey = masked.find(k => k.masked.includes('AIzaSyD'));
  assert.ok(activeKey);
  assert.ok(activeKey.masked.includes('...'));
  assert.ok(!activeKey.masked.includes('DummyTestKey')); // Never leak middle of key
});

test('3. dep_audit plugin inspects package.json', async () => {
  const res = await pluginLoader.execute('dep_audit', { target: '.' });
  assert.equal(res.success, true);
  assert.ok(res.data.scannedManifests.length >= 1);
  assert.equal(res.data.summary.CRITICAL, 0);
});

test('4. sys_ops audits system metrics', async () => {
  const res = await pluginLoader.execute('sys_ops', { checkListeningPorts: false });
  assert.equal(res.success, true);
  assert.equal(res.data.host.platform, process.platform);
  assert.ok(res.data.memory.totalMb > 0);
});

test('5. log_hunter detects SQLi and XSS payloads', async () => {
  const dummyLog = `
192.168.1.100 - - [16/Sep/2026:12:00:00 +0000] "GET /index.php?id=1' UNION SELECT username, password FROM users-- HTTP/1.1" 200 4500
192.168.1.105 - - [16/Sep/2026:12:01:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1200
192.168.1.200 - - [16/Sep/2026:12:02:00 +0000] "GET /normal/page HTTP/1.1" 200 500
  `.trim();

  const res = await pluginLoader.execute('log_hunter', { logContent: dummyLog });
  assert.equal(res.success, true);
  assert.equal(res.data.totalThreatsFound, 2);
  assert.equal(res.data.findingsByCategory.SQL_INJECTION, 1);
  assert.equal(res.data.findingsByCategory.CROSS_SITE_SCRIPTING, 1);
});

test('6. secret_scanner detects and masks leaked secrets', async () => {
  const testSecretFile = path.resolve('test_secret_sample.js');
  await fs.writeFile(testSecretFile, 'const aws = "AKIAIOSFODNN7EXAMPLE";\n', 'utf8');

  try {
    const res = await pluginLoader.execute('secret_scanner', { path: testSecretFile });
    assert.equal(res.success, true);
    assert.equal(res.data.totalFindings, 1);
    assert.equal(res.data.findings[0].rule, 'AWS Access Key ID');
    assert.ok(res.data.findings[0].masked.includes('AKIA'));
  } finally {
    await fs.unlink(testSecretFile).catch(() => {});
  }
});

test('7. iac_linter detects insecure Dockerfile instructions', async () => {
  const testDockerFile = path.resolve('Dockerfile.test.tmp');
  const dockerContent = `
FROM node:latest
COPY . /app
RUN curl -sSL https://get.docker.com | bash
CMD ["node", "app.js"]
  `.trim();
  await fs.writeFile(testDockerFile, dockerContent, 'utf8');

  try {
    const res = await pluginLoader.execute('iac_linter', { target: testDockerFile });
    assert.equal(res.success, true);
    assert.ok(res.data.totalFindings >= 3);
    const rules = res.data.findings.map(i => i.rule);
    assert.ok(rules.includes('No Non-Root USER Defined'));
    assert.ok(rules.includes('Remote Script Pipe Execution'));
    assert.ok(rules.includes('Unpinned Base Image'));
  } finally {
    await fs.unlink(testDockerFile).catch(() => {});
  }
});

test('8. code_patcher creates .bak and patches file with rollback verification', async () => {
  const testFile = path.resolve('test_code_patch.tmp');
  await fs.writeFile(testFile, 'const SECURE_MODE = false;\n', 'utf8');

  try {
    // 1. Replace patch
    const patchRes = await pluginLoader.execute('code_patcher', {
      filePath: testFile,
      operation: 'replace',
      targetString: 'SECURE_MODE = false',
      replacementContent: 'SECURE_MODE = true'
    });
    assert.equal(patchRes.success, true);
    assert.ok(patchRes.data.backupCreated);
    assert.ok(await fs.stat(patchRes.data.backupCreated));

    // Verify content changed
    const patchedContent = await fs.readFile(testFile, 'utf8');
    assert.equal(patchedContent, 'const SECURE_MODE = true;\n');

    // 2. Restore patch
    const restoreRes = await pluginLoader.execute('code_patcher', {
      filePath: testFile,
      operation: 'restore',
      backupPath: patchRes.data.backupCreated
    });
    assert.equal(restoreRes.success, true);

    // Verify content restored
    const revertedContent = await fs.readFile(testFile, 'utf8');
    assert.equal(revertedContent, 'const SECURE_MODE = false;\n');

    // Clean up backup file
    await fs.unlink(patchRes.data.backupCreated).catch(() => {});
  } finally {
    await fs.unlink(testFile).catch(() => {});
  }
});

test('9. osint_search analyzes phone number and username queries', async () => {
  // Test phone OSINT parsing
  const phoneRes = await pluginLoader.execute('osint_search', { target: '08123456789', type: 'phone' });
  assert.equal(phoneRes.success, true);
  assert.equal(phoneRes.data.type, 'PHONE_OSINT');
  assert.equal(phoneRes.data.parsed.e164Format, '+628123456789');
  assert.equal(phoneRes.data.location.country, 'Indonesia');
  assert.ok(phoneRes.data.telecom.carrier.includes('Telkomsel'));
  assert.ok(phoneRes.data.osintLinks.whatsappChat.includes('628123456789'));

  // Test username OSINT structure
  const userRes = await pluginLoader.execute('osint_search', { target: 'testuser12345', type: 'username', timeoutMs: 1500 });
  assert.equal(userRes.success, true);
  assert.equal(userRes.data.type, 'USERNAME_OSINT');
  assert.ok(userRes.data.totalPlatformsChecked >= 20);
  assert.ok(userRes.data.dorks.google.includes('testuser12345'));
});
