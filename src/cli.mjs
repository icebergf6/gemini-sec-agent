import readline from 'readline';
import { agent } from './agent.mjs';
import { keyManager, config } from './config.mjs';
import { pluginLoader } from './plugin_loader.mjs';
import {
  colors, c,
  printBanner,
  createSpinner,
  renderBox,
  renderPluginList,
  renderKeyTable,
  renderHelp,
  promptString,
  printDivider,
  logSuccess,
  logInfo,
  logWarn,
  logError
} from './ui.mjs';

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
    prompt: promptString()
  });

  // ─────────────────────── COMMAND HANDLER ────────────────────────────────────
  rl.on('line', async (line) => {
    let input = line.trim();

    if (!input) { rl.prompt(); return; }

    // Strip accidental 'agy ' prefix typed inside REPL
    if (input.startsWith('agy ')) input = input.slice(4).trim();

    // ── SYSTEM COMMANDS ────────────────────────────────────────────────────────

    if (['exit', '/exit', 'quit', '/quit', 'q'].includes(input)) {
      console.log(`\n  ${c.bYellow}👋  Sesi AGY diakhiri. Stay secure!${c.reset}\n`);
      process.exit(0);
    }

    if (['clear', '/clear', 'cls'].includes(input)) {
      console.clear();
      printBanner(agent.getModel(), keyManager.keys.length, pluginLoader.getAll().length);
      rl.setPrompt(promptString());
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

    // ── /addkey <key> ──────────────────────────────────────────────────────────
    if (input.startsWith('/addkey') || input.startsWith('addkey ')) {
      const key = input.replace(/^(?:\/addkey|addkey)\s*/, '').trim();
      if (!key) {
        logWarn('Usage: /addkey AIzaSy…');
      } else {
        keyManager.addKey(key);
        agent.initSession();
        logSuccess(`API key added. Pool size: ${c.bGreen}${keyManager.keys.length}${c.reset}`);
      }
      rl.prompt();
      return;
    }

    // ── /model [name] ──────────────────────────────────────────────────────────
    if (/^(?:\/model|model|-m|--model)(\s|$)/i.test(input)) {
      const name = input.replace(/^(?:\/model|model|-m|--model)\s*/, '').trim();
      if (name) {
        agent.setModel(name);
        logSuccess(`Model switched → ${c.bYellow}${name}${c.reset}`);
      } else {
        logInfo(`Active model: ${c.bYellow}${c.bold}${agent.getModel()}${c.reset}`);
        console.log(`  ${c.bBlack}Tip: ${c.reset}${c.dim}/model gemini-1.5-pro${c.reset}`);
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
        renderBox(`🛡️  ${name.toUpperCase()}  (${res.durationMs}ms)`, JSON.stringify(res.data, null, 2), 'green');
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
