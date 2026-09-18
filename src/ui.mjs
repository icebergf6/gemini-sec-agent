import readline from 'readline';
import os from 'os';

// ─────────────────────────────────────────────────────────────────────────────
// ANSI COLOR & STYLE PALETTE
// ─────────────────────────────────────────────────────────────────────────────
export const c = {
  reset:    '\x1b[0m',
  bold:     '\x1b[1m',
  dim:      '\x1b[2m',
  italic:   '\x1b[3m',
  under:    '\x1b[4m',

  // Foreground
  black:    '\x1b[30m',
  red:      '\x1b[31m',
  green:    '\x1b[32m',
  yellow:   '\x1b[33m',
  blue:     '\x1b[34m',
  magenta:  '\x1b[35m',
  cyan:     '\x1b[36m',
  white:    '\x1b[37m',

  // Bright Foreground
  bBlack:   '\x1b[90m',
  bRed:     '\x1b[91m',
  bGreen:   '\x1b[92m',
  bYellow:  '\x1b[93m',
  bBlue:    '\x1b[94m',
  bMagenta: '\x1b[95m',
  bCyan:    '\x1b[96m',
  bWhite:   '\x1b[97m',

  // Background
  bgBlack:   '\x1b[40m',
  bgRed:     '\x1b[41m',
  bgGreen:   '\x1b[42m',
  bgYellow:  '\x1b[43m',
  bgBlue:    '\x1b[44m',
  bgMagenta: '\x1b[45m',
  bgCyan:    '\x1b[46m',
};

// Alias for compat
export const colors = {
  reset: c.reset, bold: c.bold, dim: c.dim, italic: c.italic, underline: c.under,
  black: c.black, red: c.red, green: c.green, yellow: c.yellow, blue: c.blue,
  magenta: c.magenta, cyan: c.cyan, white: c.white,
  brightBlack: c.bBlack, brightRed: c.bRed, brightGreen: c.bGreen,
  brightYellow: c.bYellow, brightBlue: c.bBlue, brightMagenta: c.bMagenta,
  brightCyan: c.bCyan, brightWhite: c.bWhite,
  bgBlack: c.bgBlack, bgGreen: c.bgGreen, bgBlue: c.bgBlue,
  bgMagenta: c.bgMagenta, bgCyan: c.bgCyan, bgDark: c.bgBlack
};

const isTTY = Boolean(process.stdout.isTTY && !process.env.CI);
const cols  = () => Math.min(process.stdout.columns || 80, 100);

// ─────────────────────────────────────────────────────────────────────────────
// GRADIENT TEXT  (cycles through cyan → magenta gradient per character)
// ─────────────────────────────────────────────────────────────────────────────
const GRAD = ['\x1b[96m', '\x1b[95m', '\x1b[94m', '\x1b[96m', '\x1b[93m'];
function grad(text) {
  return [...text].map((ch, i) => `${GRAD[i % GRAD.length]}${ch}`).join('') + c.reset;
}

// ─────────────────────────────────────────────────────────────────────────────
// BANNER
// ─────────────────────────────────────────────────────────────────────────────
export function printBanner(modelName, keyCount, pluginCount) {
  if (!isTTY) return;

  const hr  = `${c.bBlack}${'═'.repeat(cols())}${c.reset}`;
  const hr2 = `${c.bBlack}${'─'.repeat(cols())}${c.reset}`;

  const logo = [
    `${c.bCyan}  ██████╗${c.bMagenta}  ██████╗ ${c.bBlue} ██╗   ██╗${c.reset}`,
    `${c.bCyan} ██╔══██╗${c.bMagenta}██╔════╝ ${c.bBlue}╚██╗ ██╔╝${c.reset}`,
    `${c.bCyan} ███████║${c.bMagenta}██║  ███╗${c.bBlue} ╚████╔╝ ${c.reset}`,
    `${c.bCyan} ██╔══██║${c.bMagenta}██║   ██║${c.bBlue}  ╚██╔╝  ${c.reset}`,
    `${c.bCyan} ██║  ██║${c.bMagenta}╚██████╔╝${c.bBlue}   ██║   ${c.reset}`,
    `${c.bCyan} ╚═╝  ╚═╝${c.bMagenta} ╚═════╝ ${c.bBlue}   ╚═╝   ${c.reset}`,
  ];

  const tagline = `${c.bBlack}  OVERPOWER CLI ARCHITECT & CYBERSECURITY OPERATOR${c.reset}`;

  const statusParts = [
    `${c.bgGreen}${c.black}${c.bold} ◉ ONLINE ${c.reset}`,
    `${c.bBlack}│${c.reset}`,
    `${c.bBlack}Model ${c.reset}${c.bYellow}${c.bold}${modelName}${c.reset}`,
    `${c.bBlack}│${c.reset}`,
    `${c.bBlack}Keys ${c.reset}${c.bGreen}${c.bold}${keyCount}${c.reset}`,
    `${c.bBlack}│${c.reset}`,
    `${c.bBlack}Plugins ${c.reset}${c.bMagenta}${c.bold}${pluginCount}${c.reset}`,
    `${c.bBlack}│${c.reset}`,
    `${c.bBlack}OS ${c.reset}${c.bCyan}${os.hostname()}${c.reset}`,
  ];

  const hint = `${c.bBlack}  Type a prompt, or use ${c.reset}${c.bCyan}/help${c.reset}${c.bBlack} • ${c.bMagenta}/plugins${c.reset}${c.bBlack} • ${c.bYellow}/run <plugin>${c.reset}${c.bBlack} • ${c.bRed}/exit${c.reset}`;

  console.log('\n' + hr);
  logo.forEach(l => console.log(`  ${l}`));
  console.log(tagline);
  console.log(hr);
  console.log('  ' + statusParts.join('  '));
  console.log(hr2);
  console.log(hint);
  console.log(hr2 + '\n');
}

// ─────────────────────────────────────────────────────────────────────────────
// SPINNER
// ─────────────────────────────────────────────────────────────────────────────
const FRAMES = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];

export function createSpinner(initial = 'Processing...') {
  if (!isTTY) {
    return {
      start:   () => process.stdout.write(`\n  ${c.bCyan}◌${c.reset}  ${initial}\n`),
      update:  (t) => process.stdout.write(`  ${c.bCyan}◌${c.reset}  ${t}\n`),
      stop:    () => {},
      succeed: (t) => console.log(`  ${c.bGreen}✔${c.reset}  ${t || initial}`),
      fail:    (t) => console.log(`  ${c.bRed}✖${c.reset}  ${t || initial}`)
    };
  }

  let idx = 0, timer = null, text = initial;

  const clear = () => {
    readline.clearLine(process.stdout, 0);
    readline.cursorTo(process.stdout, 0);
  };

  return {
    start() {
      process.stdout.write('\x1b[?25l');
      timer = setInterval(() => {
        clear();
        process.stdout.write(`  ${c.bCyan}${FRAMES[idx++ % FRAMES.length]}${c.reset}  ${c.dim}${text}${c.reset}`);
      }, 80);
    },
    update(t) { text = t; },
    stop() {
      if (timer) { clearInterval(timer); timer = null; }
      clear();
      process.stdout.write('\x1b[?25h');
    },
    succeed(msg) {
      if (timer) { clearInterval(timer); timer = null; }
      clear();
      process.stdout.write('\x1b[?25h');
      console.log(`  ${c.bGreen}✔${c.reset}  ${msg || text}`);
    },
    fail(msg) {
      if (timer) { clearInterval(timer); timer = null; }
      clear();
      process.stdout.write('\x1b[?25h');
      console.log(`  ${c.bRed}✖${c.reset}  ${msg || text}`);
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// RESPONSE BOX
// ─────────────────────────────────────────────────────────────────────────────
export function renderBox(title, content, style = 'cyan') {
  const colorMap = { cyan: c.bCyan, green: c.bGreen, red: c.bRed, yellow: c.bYellow, magenta: c.bMagenta };
  const col = colorMap[style] || c.bCyan;
  const w   = cols();
  const topFill = Math.max(w - title.length - 8, 2);

  console.log('');
  console.log(`  ${col}┌─── ${c.bold}${title}${c.reset} ${col}${'─'.repeat(topFill)}┐${c.reset}`);
  console.log(`  ${col}│${c.reset}`);
  const lines = content.split('\n');
  for (const line of lines) {
    console.log(`  ${col}│${c.reset}  ${line}`);
  }
  console.log(`  ${col}│${c.reset}`);
  console.log(`  ${col}└${'─'.repeat(w - 2)}┘${c.reset}`);
  console.log('');
}

// ─────────────────────────────────────────────────────────────────────────────
// PLUGIN CARD
// ─────────────────────────────────────────────────────────────────────────────
export function renderPluginList(plugins) {
  const w = cols();
  console.log('');
  console.log(`  ${c.bMagenta}${c.bold}┌${'─'.repeat(w - 4)}┐${c.reset}`);
  console.log(`  ${c.bMagenta}│${c.reset}  ${c.bold}${c.bMagenta}🛡️  CYBERSECURITY & DEVSECOPS PLUGIN REGISTRY${c.reset}${' '.repeat(Math.max(0, w - 50))}${c.bMagenta}│${c.reset}`);
  console.log(`  ${c.bMagenta}├${'─'.repeat(w - 4)}┤${c.reset}`);

  if (plugins.length === 0) {
    console.log(`  ${c.bMagenta}│${c.reset}  ${c.dim}No plugins loaded. Add .mjs files to the plugins/ folder.${c.reset}`);
  } else {
    const icons = { web_audit:'🌐', port_scanner:'📡', secret_scanner:'🔑', iac_linter:'🐳', log_hunter:'🔍', dep_audit:'📦', sys_ops:'🖥️', code_patcher:'🛠️', osint_search:'🔎' };
    plugins.forEach((p, i) => {
      const icon = icons[p.name] || '⚙️';
      const num  = `${c.bBlack}${String(i + 1).padStart(2, ' ')}.${c.reset}`;
      const nm   = `${c.bold}${c.bCyan}${p.name.padEnd(18)}${c.reset}`;
      const desc = `${c.dim}${p.description.substring(0, 56)}${p.description.length > 56 ? '…' : ''}${c.reset}`;
      console.log(`  ${c.bMagenta}│${c.reset}  ${num} ${icon}  ${nm}  ${desc}`);
    });
  }
  console.log(`  ${c.bMagenta}├${'─'.repeat(w - 4)}┤${c.reset}`);
  console.log(`  ${c.bMagenta}│${c.reset}  ${c.bBlack}Usage: ${c.reset}${c.bCyan}/run <plugin_name> [args]${c.reset}   ${c.bBlack}Direct: ${c.reset}${c.bYellow}agy --run-plugin <name> [args]${c.reset}`);
  console.log(`  ${c.bMagenta}└${'─'.repeat(w - 4)}┘${c.reset}`);
  console.log('');
}

// ─────────────────────────────────────────────────────────────────────────────
// KEYS STATUS TABLE
// ─────────────────────────────────────────────────────────────────────────────
export function renderKeyTable(maskedKeys) {
  console.log('');
  console.log(`  ${c.bCyan}${c.bold}🔑  API KEY ROTATION POOL${c.reset}`);
  console.log(`  ${c.bBlack}${'─'.repeat(44)}${c.reset}`);
  if (maskedKeys.length === 0) {
    console.log(`  ${c.dim}  (empty — use /addkey <key> to register)${c.reset}`);
  } else {
    maskedKeys.forEach(k => {
      const badge = k.active
        ? `${c.bgGreen}${c.black}${c.bold} ● ACTIVE  ${c.reset}`
        : `${c.bgBlack}${c.bBlack}  STANDBY ${c.reset}`;
      console.log(`  ${badge}  ${c.bBlack}Key #${k.index}${c.reset}  ${c.bYellow}${k.masked}${c.reset}`);
    });
  }
  console.log(`  ${c.bBlack}${'─'.repeat(44)}${c.reset}\n`);
}

// ─────────────────────────────────────────────────────────────────────────────
// HELP TABLE
// ─────────────────────────────────────────────────────────────────────────────
export function renderHelp() {
  const w   = cols();
  const row = (cmd, desc) =>
    `  ${c.bMagenta}│${c.reset}  ${c.bold}${c.bCyan}${cmd.padEnd(30)}${c.reset}  ${c.dim}${desc}${c.reset}`;

  console.log('');
  console.log(`  ${c.bMagenta}┌${'─'.repeat(w - 4)}┐${c.reset}`);
  console.log(`  ${c.bMagenta}│${c.reset}  ${c.bold}${c.bMagenta}⚡  AGY COMMAND REFERENCE${c.reset}`);
  console.log(`  ${c.bMagenta}├──────────────────────────── SLASH COMMANDS ─${('─').repeat(Math.max(0, w - 50))}┤${c.reset}`);
  console.log(row('/help  · -h',            'Show this help menu'));
  console.log(row('/search <target>',       'OSINT search for username or phone number'));
  console.log(row('/plugins',               'List all loaded cybersecurity plugins'));
  console.log(row('/run <plugin> [args]',   'Execute plugin directly (no LLM)'));
  console.log(row('/model [name]',          'View or switch active Gemini model'));
  console.log(row('/keys',                  'Show API key rotation pool status'));
  console.log(row('/addkey <key>',          'Add a new API key to session pool'));
  console.log(row('/reload',                'Hot-reload all plugins from disk'));
  console.log(row('/clear  · cls',          'Clear screen and reprint banner'));
  console.log(row('/exit   · quit',         'Exit AGY terminal session'));
  console.log(`  ${c.bMagenta}├────────────────────────────── CLI FLAGS ─────${('─').repeat(Math.max(0, w - 51))}┤${c.reset}`);
  console.log(row('agy -p "prompt"',        'One-shot prompt (non-interactive)'));
  console.log(row('agy --run-plugin <n>',   'Execute plugin directly from shell'));
  console.log(row('agy --list-plugins',     'List plugins and exit'));
  console.log(row('agy --keys',             'Show API key pool and exit'));
  console.log(row('agy --json',             'Machine-readable JSON output (pipe to jq)'));
  console.log(row('cat file | agy "query"', 'Pipe content into AGY for analysis'));
  console.log(`  ${c.bMagenta}└${'─'.repeat(w - 4)}┘${c.reset}\n`);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION DIVIDER
// ─────────────────────────────────────────────────────────────────────────────
export function printDivider(label = '') {
  const w = cols();
  if (!label) {
    console.log(`  ${c.bBlack}${'─'.repeat(w - 4)}${c.reset}`);
    return;
  }
  const pad = Math.max(0, w - 4 - label.length - 4);
  console.log(`  ${c.bBlack}── ${label} ${'─'.repeat(pad)}${c.reset}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// NOTIFICATION HELPERS
// ─────────────────────────────────────────────────────────────────────────────
export function logSuccess(msg) {
  console.log(`\n  ${c.bGreen}✔${c.reset}  ${msg}`);
}
export function logInfo(msg) {
  console.log(`\n  ${c.bCyan}ℹ${c.reset}  ${msg}`);
}
export function logWarn(msg) {
  console.log(`\n  ${c.bYellow}⚠${c.reset}  ${msg}`);
}
export function logError(msg) {
  console.error(`\n  ${c.bRed}✖${c.reset}  ${c.bRed}${msg}${c.reset}`);
}
export function logToolCall(name, args) {
  const short = JSON.stringify(args || {});
  console.log(`\n  ${c.bMagenta}⚡${c.reset}  ${c.bold}PLUGIN${c.reset} ${c.bCyan}${name}${c.reset}  ${c.bBlack}${short}${c.reset}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// PROMPT INDICATOR  (returns a styled REPL prompt string)
// ─────────────────────────────────────────────────────────────────────────────
export function promptString() {
  return `\n  ${c.bBlack}┌─${c.reset} ${c.bMagenta}${c.bold}AGY${c.reset} ${c.bBlack}›${c.reset} `;
}
