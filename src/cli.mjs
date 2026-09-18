import readline from 'readline';
import fs from 'fs';
import path from 'path';
import { agent } from './agent.mjs';
import { keyManager, config } from './config.mjs';
import { pluginLoader } from './plugin_loader.mjs';
import { generateReport, formatTerminal, formatMarkdown, formatJSON, writeReport } from './report.mjs';
import { sanitizeInput, isPhoneLike } from './utils.mjs';
import {
  colors, c,
  printBanner,
  createSpinner,
  renderBox,
  renderPluginList,
  renderKeyTable,
  renderHelp,
  renderKitMenu,
  promptString,
  printDivider,
  logSuccess,
  logInfo,
  logWarn,
  logError
} from './ui.mjs';

// ─────────────────────────────────────────────────────────────────────────────
// SESSION STATE
// ─────────────────────────────────────────────────────────────────────────────
const sessionHistory = [];    // Command history
let lastResult = null;        // Last tool execution result (for /export)
let lastPluginName = '';      // Last plugin name used

function recordHistory(cmd) {
  sessionHistory.push({ cmd, timestamp: new Date().toISOString() });
  if (sessionHistory.length > 50) sessionHistory.shift();
}

function storeLastResult(data, pluginName, durationMs) {
  lastResult = { data, pluginName, durationMs };
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI ARGS PARSER  (resilient against PowerShell quoting quirks)
// ─────────────────────────────────────────────────────────────────────────────
export function parseCliArgs(raw) {
  if (!raw || raw === '{}') return {};
  if (typeof raw === 'object') return raw;

  const str = String(raw).trim();

  // 1. Valid JSON
  try { return JSON.parse(str); } catch {}

  // 2. Single-quoted / unquoted JSON-ish
  try {
    const norm = str
      .replace(/'/g, '"')
      .replace(/([{,])\s*([a-zA-Z0-9_]+)\s*:/g, '$1"$2":')
      .replace(/:\s*([a-zA-Z0-9_.\-/]+)(?=[,}])/g, ':"$1"');
    return JSON.parse(norm);
  } catch {}

  // 3. k=v / k:v pairs
  const result = {};
  const inner = str.replace(/^[{"']+|[}"']+$/g, '');
  for (const entry of inner.split(/[,;]+/)) {
    const t = entry.trim();
    const sep = t.search(/[:=]/);
    if (sep > 0) {
      const k = t.slice(0, sep).trim();
      const v = t.slice(sep + 1).trim().replace(/^["']+|["']+$/g, '');
      result[k] = v;
    }
  }
  if (Object.keys(result).length > 0) return result;

  // 4. Plain string fallback
  const clean = str.replace(/^[{"']+|[}"']+$/g, '');
  return { target: clean, path: clean, logPath: clean, filePath: clean };
}

// ─────────────────────────────────────────────────────────────────────────────
// ONE-SHOT (non-interactive) execution
// ─────────────────────────────────────────────────────────────────────────────
export async function runOneShot(prompt, opts = {}) {
  await pluginLoader.loadPlugins();
  if (opts.model) agent.setModel(opts.model);

  const spinner = createSpinner('AGY is thinking…');
  if (!opts.json) spinner.start();

  try {
    const result = await agent.sendMessage(prompt, (t) => {
      if (!opts.json) spinner.update(t);
    });
    if (!opts.json) {
      spinner.stop();
      renderBox('🤖  AGY RESPONSE', result, 'cyan');
    } else {
      console.log(JSON.stringify({ status: 'success', model: agent.getModel(), prompt, response: result }, null, 2));
    }
  } catch (err) {
    if (!opts.json) {
      spinner.fail('Failed to get response');
      logError(err.message);
    } else {
      console.error(JSON.stringify({ status: 'error', error: err.message }, null, 2));
    }
    process.exit(1);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// OSINT & RESEARCH TOOLKIT EXECUTORS (with integrated report layer)
// ─────────────────────────────────────────────────────────────────────────────
export async function executeUsernameSearch(target, opts = {}) {
  await pluginLoader.loadPlugins();
  const cleanTarget = sanitizeInput(String(target || ''));
  if (!cleanTarget) {
    logWarn('Target username tidak boleh kosong.');
    return;
  }
  const spinner = createSpinner(`Melakukan pemindaian akun @${c.bCyan}${cleanTarget}${c.reset} di 20+ platform…`);
  if (!opts.json) spinner.start();
  const res = await pluginLoader.execute('osint_search', { target: cleanTarget, type: 'username' });
  if (!opts.json) spinner.stop();

  if (opts.json) {
    console.log(formatJSON(res.data, { pluginName: 'osint_search', durationMs: res.durationMs }));
    return;
  }

  if (res.success) {
    storeLastResult(res.data, 'osint_search', res.durationMs);
    const output = formatTerminal(res.data, { pluginName: 'osint_search', durationMs: res.durationMs });
    renderBox(`👤 OSINT USERNAME FOOTPRINT (${res.durationMs}ms)`, output, 'cyan');

    // Auto-save report
    if (opts.report) {
      const filePath = writeReport(
        formatMarkdown(res.data, { pluginName: 'osint_search', durationMs: res.durationMs }),
        { pluginName: `username-${cleanTarget}` }
      );
      logSuccess(`Laporan disimpan: ${c.bCyan}${filePath}${c.reset}`);
    }
  } else {
    logError(res.error);
  }
}

export async function executePhoneSearch(target, opts = {}) {
  await pluginLoader.loadPlugins();
  const cleanTarget = sanitizeInput(String(target || ''));
  if (!cleanTarget) {
    logWarn('Target nomor telepon tidak boleh kosong.');
    return;
  }
  const spinner = createSpinner(`Melakukan analisis intelijen nomor ${c.bCyan}${cleanTarget}${c.reset}…`);
  if (!opts.json) spinner.start();
  const res = await pluginLoader.execute('osint_search', { target: cleanTarget, type: 'phone' });
  if (!opts.json) spinner.stop();

  if (opts.json) {
    console.log(formatJSON(res.data, { pluginName: 'osint_search', durationMs: res.durationMs }));
    return;
  }

  if (res.success) {
    storeLastResult(res.data, 'osint_search', res.durationMs);
    const output = formatTerminal(res.data, { pluginName: 'osint_search', durationMs: res.durationMs });
    renderBox(`📞 OSINT PHONE & TELECOM INTELLIGENCE (${res.durationMs}ms)`, output, 'green');

    if (opts.report) {
      const filePath = writeReport(
        formatMarkdown(res.data, { pluginName: 'osint_search', durationMs: res.durationMs }),
        { pluginName: `phone-${cleanTarget.replace(/\+/g, '')}` }
      );
      logSuccess(`Laporan disimpan: ${c.bCyan}${filePath}${c.reset}`);
    }
  } else {
    logError(res.error);
  }
}

export async function executeInfoResearch(query, opts = {}) {
  await pluginLoader.loadPlugins();
  const cleanQuery = sanitizeInput(String(query || ''));
  if (!cleanQuery) {
    logWarn('Query/topik penelitian intelijen tidak boleh kosong.');
    return;
  }
  const spinner = createSpinner(`Menjalankan penelitian intelijen mendalam via Gemini AI untuk "${cleanQuery}"…`);
  if (!opts.json) spinner.start();
  try {
    const prompt = `Lakukan analisis intelijen mendalam (Deep OSINT / Technical Intelligence Investigation) mengenai target/topik berikut:
"${cleanQuery}"

Format laporan terstruktur:
1. 🎯 Identifikasi & Profil Singkat Target / Topik
2. 🔬 Analisis Teknis, Vektor Keamanan & Jejak Publik
3. ⚠️ Penilaian Risiko (Threat Landscape & Potential Exposure)
4. 🛠️ Langkah Investigasi Lanjutan & Rekomendasi Mitigasi / Sumber Verifikasi`;

    const startTime = Date.now();
    const result = await agent.sendMessage(prompt, (t) => {
      if (!opts.json) spinner.update(t);
    });
    const durationMs = Date.now() - startTime;

    if (!opts.json) {
      spinner.stop();
      storeLastResult({ query: cleanQuery, intelligence: result }, 'deep_intel', durationMs);
      renderBox(`🔬 DEEP INTEL RESEARCH: ${cleanQuery.toUpperCase()}`, result, 'magenta');

      if (opts.report) {
        const mdContent = `# 🔬 Deep Intelligence Research Report\n\n**Query:** ${cleanQuery}\n**Duration:** ${durationMs}ms\n**Timestamp:** ${new Date().toISOString()}\n\n---\n\n${result}\n\n---\n*Generated by AGY Gemini Sec Agent*`;
        const filePath = writeReport(mdContent, { pluginName: `intel-${cleanQuery.slice(0, 30).replace(/\s+/g, '_')}` });
        logSuccess(`Laporan disimpan: ${c.bCyan}${filePath}${c.reset}`);
      }
    } else {
      console.log(JSON.stringify({ status: 'success', query: cleanQuery, intelligence: result, durationMs }, null, 2));
    }
  } catch (err) {
    if (!opts.json) {
      spinner.fail('Gagal mendapatkan respon intelijen');
      logError(err.message);
    } else {
      console.error(JSON.stringify({ status: 'error', error: err.message }, null, 2));
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// INTERACTIVE REPL
// ─────────────────────────────────────────────────────────────────────────────
export async function startInteractiveREPL() {
  const plugins = await pluginLoader.loadPlugins();
  printBanner(agent.getModel(), keyManager.keys.length, plugins.length);

  if (keyManager.keys.length === 0) {
    logWarn(
      'No GEMINI_API_KEY detected!\n' +
      '  Use /addkey <YOUR_KEY>  or create a .env file in the project folder.'
    );
  }

  const rl = readline.createInterface({
    input:  process.stdin,
    output: process.stdout,
    prompt: promptString(agent.getModel())
  });

  // ─────────────────────── COMMAND HANDLER ────────────────────────────────────
  rl.on('line', async (line) => {
    let input = line.trim();

    if (!input) { rl.prompt(); return; }

    // Strip accidental 'agy ' prefix typed inside REPL
    if (input.startsWith('agy ')) input = input.slice(4).trim();

    // Record history
    recordHistory(input);

    // ── SYSTEM COMMANDS ────────────────────────────────────────────────────────

    if (['exit', '/exit', 'quit', '/quit', 'q'].includes(input)) {
      console.log(`\n  ${c.bYellow}👋  Sesi AGY diakhiri. Stay secure!${c.reset}\n`);
      process.exit(0);
    }

    if (['clear', '/clear', 'cls'].includes(input)) {
      console.clear();
      printBanner(agent.getModel(), keyManager.keys.length, pluginLoader.getAll().length);
      rl.setPrompt(promptString(agent.getModel()));
      rl.prompt();
      return;
    }

    if (['-h', '--help', 'help', '/help'].includes(input)) {
      renderHelp();
      rl.prompt();
      return;
    }

    if (['/keys', 'keys', '--keys'].includes(input)) {
      renderKeyTable(keyManager.getMaskedKeys());
      rl.prompt();
      return;
    }

    if (['/plugins', 'plugins', '--list-plugins'].includes(input)) {
      renderPluginList(pluginLoader.getAll());
      rl.prompt();
      return;
    }

    if (['/reload', 'reload'].includes(input)) {
      const reloaded = await pluginLoader.loadPlugins();
      agent.initSession();
      logSuccess(`${c.bMagenta}${reloaded.length}${c.reset} plugins hot-reloaded.`);
      rl.prompt();
      return;
    }

    // ── /history ──────────────────────────────────────────────────────────────
    if (['/history', 'history'].includes(input)) {
      console.log('');
      console.log(`  ${c.bCyan}${c.bold}📜  SESSION COMMAND HISTORY${c.reset}`);
      console.log(`  ${c.bBlack}${'─'.repeat(60)}${c.reset}`);
      if (sessionHistory.length === 0) {
        console.log(`  ${c.dim}  (No commands recorded yet)${c.reset}`);
      } else {
        const recent = sessionHistory.slice(-15);
        recent.forEach((h, i) => {
          const time = h.timestamp.split('T')[1].slice(0, 8);
          console.log(`  ${c.bBlack}${String(i + 1).padStart(3)}.${c.reset} ${c.dim}[${time}]${c.reset} ${c.bCyan}${h.cmd}${c.reset}`);
        });
      }
      console.log(`  ${c.bBlack}${'─'.repeat(60)}${c.reset}\n`);
      rl.prompt();
      return;
    }

    // ── /export [format] ─────────────────────────────────────────────────────
    if (/^(?:\/export|export)(\s|$)/i.test(input)) {
      if (!lastResult) {
        logWarn('Belum ada hasil yang bisa diekspor. Jalankan perintah terlebih dahulu.');
        rl.prompt();
        return;
      }
      const formatArg = input.replace(/^(?:\/export|export)\s*/i, '').trim().toLowerCase() || 'md';
      const fmt = ['json', 'md', 'markdown'].includes(formatArg) ? formatArg : 'md';
      const { data, pluginName, durationMs } = lastResult;

      let content;
      if (fmt === 'json') {
        content = formatJSON(data, { pluginName, durationMs });
      } else {
        content = formatMarkdown(data, { pluginName, durationMs });
      }

      const filePath = writeReport(content, {
        format: fmt === 'json' ? 'json' : 'md',
        pluginName: pluginName || 'report'
      });
      logSuccess(`Laporan berhasil disimpan: ${c.bCyan}${filePath}${c.reset}`);
      rl.prompt();
      return;
    }

    // ── /addkey <key> ──────────────────────────────────────────────────────────
    if (input.startsWith('/addkey') || input.startsWith('addkey ')) {
      const key = input.replace(/^(?:\/addkey|addkey)\s*/, '').trim();
      if (!key) {
        logWarn('Usage: /addkey AIzaSy…');
      } else {
        keyManager.addKey(key);
        agent.initSession();
        logSuccess(`API key added. Pool size: ${c.bGreen}${keyManager.keys.length}${c.reset}`);
        // Security: clear readline history to prevent key leakage
        if (rl.history) {
          rl.history = rl.history.filter(h => !h.includes(key));
        }
      }
      rl.prompt();
      return;
    }

    // ── /model [name] ──────────────────────────────────────────────────────────
    if (/^(?:\/model|model|-m|--model)(\s|$)/i.test(input)) {
      const name = input.replace(/^(?:\/model|model|-m|--model)\s*/, '').trim();
      if (name) {
        agent.setModel(name);
        rl.setPrompt(promptString(agent.getModel()));
        logSuccess(`Model switched → ${c.bYellow}${name}${c.reset}`);
      } else {
        logInfo(`Active model: ${c.bYellow}${c.bold}${agent.getModel()}${c.reset}`);
        console.log(`  ${c.bBlack}Tip: ${c.reset}${c.dim}/model gemini-1.5-pro${c.reset}`);
      }
      rl.prompt();
      return;
    }

    // ── /kit [1|2|3|4|username|phone|info|search] [target] ──────────────────
    if (/^(?:\/kit|kit)(\s|$)/i.test(input)) {
      const rest = input.replace(/^(?:\/kit|kit)\s*/i, '').trim();

      if (rest.startsWith('1') || rest.startsWith('username')) {
        const subTarget = rest.replace(/^(?:1|username)\s*/i, '').trim();
        if (subTarget) {
          await executeUsernameSearch(subTarget);
          rl.prompt();
        } else {
          rl.question(`  ${c.bYellow}👤 Masukkan username target:${c.reset} `, async (ans) => {
            if (ans.trim()) await executeUsernameSearch(ans.trim());
            rl.prompt();
          });
        }
        return;
      }

      if (rest.startsWith('2') || rest.startsWith('phone')) {
        const subTarget = rest.replace(/^(?:2|phone)\s*/i, '').trim();
        if (subTarget) {
          await executePhoneSearch(subTarget);
          rl.prompt();
        } else {
          rl.question(`  ${c.bGreen}📞 Masukkan nomor telepon (+62/08):${c.reset} `, async (ans) => {
            if (ans.trim()) await executePhoneSearch(ans.trim());
            rl.prompt();
          });
        }
        return;
      }

      if (rest.startsWith('3') || rest.startsWith('info')) {
        const subQuery = rest.replace(/^(?:3|info)\s*/i, '').trim();
        if (subQuery) {
          await executeInfoResearch(subQuery);
          rl.prompt();
        } else {
          rl.question(`  ${c.bMagenta}🔬 Masukkan topik/query penelitian intelijen:${c.reset} `, async (ans) => {
            if (ans.trim()) await executeInfoResearch(ans.trim());
            rl.prompt();
          });
        }
        return;
      }

      if (rest.startsWith('4') || rest.startsWith('search')) {
        const subTarget = rest.replace(/^(?:4|search)\s*/i, '').trim();
        if (subTarget) {
          if (isPhoneLike(subTarget)) {
            await executePhoneSearch(subTarget);
          } else {
            await executeUsernameSearch(subTarget);
          }
          rl.prompt();
        } else {
          rl.question(`  ${c.bCyan}🔎 Masukkan target (username atau nomor telepon):${c.reset} `, async (ans) => {
            const t = ans.trim();
            if (t) {
              if (isPhoneLike(t)) {
                await executePhoneSearch(t);
              } else {
                await executeUsernameSearch(t);
              }
            }
            rl.prompt();
          });
        }
        return;
      }

      // If user typed: /kit <anything_else>
      if (rest) {
        if (isPhoneLike(rest)) {
          await executePhoneSearch(rest);
        } else {
          await executeUsernameSearch(rest);
        }
        rl.prompt();
        return;
      }

      // Default /kit without args -> show interactive menu
      renderKitMenu();
      rl.question(`  ${c.bCyan}Pilih opsi [1/2/3/4] atau ketik query:${c.reset} `, async (choice) => {
        const ch = choice.trim();
        if (!ch) { rl.prompt(); return; }

        if (ch === '1' || ch.toLowerCase() === 'username') {
          rl.question(`  ${c.bYellow}👤 Masukkan username target:${c.reset} `, async (ans) => {
            if (ans.trim()) await executeUsernameSearch(ans.trim());
            rl.prompt();
          });
        } else if (ch === '2' || ch.toLowerCase() === 'phone') {
          rl.question(`  ${c.bGreen}📞 Masukkan nomor telepon (+62/08):${c.reset} `, async (ans) => {
            if (ans.trim()) await executePhoneSearch(ans.trim());
            rl.prompt();
          });
        } else if (ch === '3' || ch.toLowerCase() === 'info') {
          rl.question(`  ${c.bMagenta}🔬 Masukkan topik/query penelitian intelijen:${c.reset} `, async (ans) => {
            if (ans.trim()) await executeInfoResearch(ans.trim());
            rl.prompt();
          });
        } else if (ch === '4' || ch.toLowerCase() === 'search') {
          rl.question(`  ${c.bCyan}🔎 Masukkan target (username/nomor):${c.reset} `, async (ans) => {
            const t = ans.trim();
            if (t) {
              if (isPhoneLike(t)) await executePhoneSearch(t);
              else await executeUsernameSearch(t);
            }
            rl.prompt();
          });
        } else if (ch.startsWith('1 ') || ch.startsWith('username ')) {
          await executeUsernameSearch(ch.replace(/^(?:1|username)\s+/i, ''));
          rl.prompt();
        } else if (ch.startsWith('2 ') || ch.startsWith('phone ')) {
          await executePhoneSearch(ch.replace(/^(?:2|phone)\s+/i, ''));
          rl.prompt();
        } else if (ch.startsWith('3 ') || ch.startsWith('info ')) {
          await executeInfoResearch(ch.replace(/^(?:3|info)\s+/i, ''));
          rl.prompt();
        } else if (ch.startsWith('4 ') || ch.startsWith('search ')) {
          const t = ch.replace(/^(?:4|search)\s+/i, '');
          if (isPhoneLike(t)) await executePhoneSearch(t);
          else await executeUsernameSearch(t);
          rl.prompt();
        } else {
          if (isPhoneLike(ch)) {
            await executePhoneSearch(ch);
          } else {
            await executeUsernameSearch(ch);
          }
          rl.prompt();
        }
      });
      return;
    }

    // ── /username <target> ─────────────────────────────────────────────────────
    if (/^(?:\/username|username)(\s|$)/i.test(input)) {
      const target = input.replace(/^(?:\/username|username)\s*/i, '').trim();
      if (!target) {
        rl.question(`  ${c.bYellow}👤 Masukkan username target:${c.reset} `, async (ans) => {
          if (ans.trim()) await executeUsernameSearch(ans.trim());
          rl.prompt();
        });
        return;
      }
      await executeUsernameSearch(target);
      rl.prompt();
      return;
    }

    // ── /phone <number> ────────────────────────────────────────────────────────
    if (/^(?:\/phone|phone|\/phonenumber|phonenumber)(\s|$)/i.test(input)) {
      const target = input.replace(/^(?:\/phone|phone|\/phonenumber|phonenumber)\s*/i, '').trim();
      if (!target) {
        rl.question(`  ${c.bGreen}📞 Masukkan nomor telepon (+62/08):${c.reset} `, async (ans) => {
          if (ans.trim()) await executePhoneSearch(ans.trim());
          rl.prompt();
        });
        return;
      }
      await executePhoneSearch(target);
      rl.prompt();
      return;
    }

    // ── /info <query> ──────────────────────────────────────────────────────────
    if (/^(?:\/info|info)(\s|$)/i.test(input)) {
      const query = input.replace(/^(?:\/info|info)\s*/i, '').trim();
      if (!query) {
        rl.question(`  ${c.bMagenta}🔬 Masukkan topik/query penelitian intelijen:${c.reset} `, async (ans) => {
          if (ans.trim()) await executeInfoResearch(ans.trim());
          rl.prompt();
        });
        return;
      }
      await executeInfoResearch(query);
      rl.prompt();
      return;
    }

    // ── /search <query> (Universal Auto-Detection) ──────────────────────────────
    if (/^(?:\/search|search)(\s|$)/i.test(input)) {
      const rest = input.replace(/^(?:\/search|search)\s*/i, '').trim();
      if (!rest) {
        rl.question(`  ${c.bCyan}🔎 Masukkan target (username atau nomor telepon):${c.reset} `, async (ans) => {
          const t = ans.trim();
          if (t) {
            if (isPhoneLike(t)) {
              await executePhoneSearch(t);
            } else {
              await executeUsernameSearch(t);
            }
          }
          rl.prompt();
        });
        return;
      }
      if (isPhoneLike(rest)) {
        await executePhoneSearch(rest);
      } else {
        await executeUsernameSearch(rest);
      }
      rl.prompt();
      return;
    }

    // ── /run <plugin> [args] ───────────────────────────────────────────────────
    const isRunCmd = /^(?:\/run|run|--run-plugin)\s+/i.test(input);
    if (isRunCmd) {
      const rest  = input.replace(/^(?:\/run|run|--run-plugin)\s+/i, '').trim();
      const parts = rest.split(/\s+/);
      const name  = parts[0];
      const args  = parseCliArgs(parts.slice(1).join(' '));

      if (!name) {
        logWarn('Usage: /run <plugin_name> [args]');
        rl.prompt();
        return;
      }

      const spinner = createSpinner(`Running plugin ${c.bCyan}${name}${c.reset}…`);
      spinner.start();
      const res = await pluginLoader.execute(name, args);
      spinner.stop();

      if (res.success) {
        storeLastResult(res.data, name, res.durationMs);
        const output = formatTerminal(res.data, { pluginName: name, durationMs: res.durationMs });
        renderBox(`🛡️  ${name.toUpperCase()}  (${res.durationMs}ms)`, output, 'green');
      } else {
        logError(res.error);
      }
      rl.prompt();
      return;
    }

    // ── Strip -p / --prompt ────────────────────────────────────────────────────
    if (/^(?:-p|--prompt)\s/i.test(input)) {
      input = input.replace(/^(?:-p|--prompt)\s+/, '').replace(/^["']|["']$/g, '');
    }

    // ── AI AGENT ───────────────────────────────────────────────────────────────
    const spinner = createSpinner('AGY is thinking…');
    spinner.start();
    try {
      const response = await agent.sendMessage(input, (t) => spinner.update(t));
      spinner.stop();
      renderBox('🤖  AGY', response, 'cyan');
    } catch (err) {
      spinner.fail('Error from Gemini API');
      logError(err.message);
    }

    rl.prompt();
  });

  rl.on('close', () => {
    console.log(`\n  ${c.bYellow}Session ended.${c.reset}\n`);
    process.exit(0);
  });

  rl.prompt();
}

// Legacy alias for one-shot help
export function showHelp() {
  renderHelp();
}
