#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { startInteractiveREPL, runOneShot, showHelp, parseCliArgs } from '../src/cli.mjs';
import { pluginLoader } from '../src/plugin_loader.mjs';
import { keyManager, config } from '../src/config.mjs';
import { colors, c, logSuccess, logError, logWarn, renderBox, renderPluginList, renderKeyTable } from '../src/ui.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pkgPath = path.resolve(__dirname, '..', 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

// Graceful termination handling
process.on('SIGINT', () => {
  console.log(`\n  ${c.bYellow}⚠  Session interrupted. Goodbye!${c.reset}\n`);
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log(`\n  ${c.bYellow}⚠  SIGTERM received. Shutting down.${c.reset}\n`);
  process.exit(0);
});

// Main execution router
async function main() {
  const args = process.argv.slice(2);

  if (args.includes('-h') || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log(`AGY CLI v${pkg.version}`);
    process.exit(0);
  }

  if (args.includes('--list-plugins')) {
    const plugins = await pluginLoader.loadPlugins();
    renderPluginList(plugins);
    process.exit(0);
  }

  if (args.includes('--keys')) {
    renderKeyTable(keyManager.getMaskedKeys());
    process.exit(0);
  }

  // OSINT search CLI flag
  const searchIdx = args.indexOf('--search');
  if (searchIdx !== -1) {
    const target = args[searchIdx + 1];
    if (!target) {
      logError('Target username or phone number required. Example: agy --search octocat');
      process.exit(1);
    }
    await pluginLoader.loadPlugins();
    const result = await pluginLoader.execute('osint_search', { target });
    if (args.includes('--json')) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      if (result.success) {
        renderBox(`🔎 OSINT SEARCH RESULT`, JSON.stringify(result.data, null, 2), 'cyan');
      } else {
        logError(result.error);
      }
    }
    process.exit(result.success ? 0 : 1);
  }

  // Direct plugin execution flag
  const runPluginIdx = args.indexOf('--run-plugin');
  if (runPluginIdx !== -1) {
    const pluginName = args[runPluginIdx + 1];
    if (!pluginName) {
      logError('Plugin name required.  Example: agy --run-plugin web_audit \'{"target":"https://example.com"}\'');
      process.exit(1);
    }
    const rawArgs = args[runPluginIdx + 2] || '{}';
    const parsedArgs = parseCliArgs(rawArgs);

    await pluginLoader.loadPlugins();
    const result = await pluginLoader.execute(pluginName, parsedArgs);
    if (args.includes('--json')) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      if (result.success) {
        renderBox(`HASIL PLUGIN: ${pluginName}`, JSON.stringify(result.data, null, 2), 'green');
      } else {
        logError(result.error);
      }
    }
    process.exit(result.success ? 0 : 1);
  }

  // Model override flag
  let modelOverride = null;
  const modelIdx = args.indexOf('-m') !== -1 ? args.indexOf('-m') : args.indexOf('--model');
  if (modelIdx !== -1 && args[modelIdx + 1]) {
    modelOverride = args[modelIdx + 1];
  }

  // One-shot prompt flag
  const promptIdx = args.indexOf('-p') !== -1 ? args.indexOf('-p') : args.indexOf('--prompt');
  if (promptIdx !== -1 && args[promptIdx + 1]) {
    const promptText = args[promptIdx + 1];
    await runOneShot(promptText, {
      model: modelOverride,
      json: args.includes('--json')
    });
    process.exit(0);
  }

  // Check if stdin is piped (e.g. cat file.log | agy "search errors")
  if (!process.stdin.isTTY) {
    let pipedData = '';
    for await (const chunk of process.stdin) {
      pipedData += chunk;
    }
    const extraPrompt = args.filter(a => !a.startsWith('-')).join(' ');
    const fullPrompt = extraPrompt
      ? `${extraPrompt}\n\n[INPUT DATA]:\n${pipedData}`
      : `Analisis data input berikut dari perspektif keamanan sistem:\n\n${pipedData}`;

    await runOneShot(fullPrompt, {
      model: modelOverride,
      json: args.includes('--json')
    });
    process.exit(0);
  }

  // If positional arguments provided without flags
  const positionalArgs = args.filter(a => !a.startsWith('-'));
  if (positionalArgs.length > 0) {
    const promptText = positionalArgs.join(' ');
    await runOneShot(promptText, {
      model: modelOverride,
      json: args.includes('--json')
    });
    process.exit(0);
  }

  // Start Interactive REPL
  await startInteractiveREPL();
}

main().catch(err => {
  logError(`Fatal exception: ${err.message}`);
  process.exit(1);
});
