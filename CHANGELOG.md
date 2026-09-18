# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-09-19

### 🚀 Added
- **Unified Reporting Layer (`src/report.mjs`)**:
  - Structured reporting engine supporting Terminal (rich ANSI formatting), Markdown (`.md`), and standard JSON formats.
  - Automatic report persistence to `reports/` folder.
  - Context-aware presentation specialized for OSINT footprinting, phone intelligence, security audits, secret scanning, dependency auditing, port scanning, web auditing, log hunting, and code patching.
- **Session Export & History**:
  - `/export [json|md]` command to export the result of the last executed tool/plugin to disk on demand.
  - `/history` command to inspect interactive session command history with timestamps.
  - Command line flag `--report` on all CLI execution paths (`--username`, `--phone`, `--info`, `--search`, `--run-plugin`).
- **Interactive OSINT Kit Enhancements (`/kit`)**:
  - Option `[4] /search`: Unified intelligent scanner that automatically differentiates usernames from phone numbers (Indonesian & International E.164 formats).
  - Streamlined nested prompts for `/kit 1`, `/kit 2`, `/kit 3`, and `/kit 4`.
  - Direct shortcuts: `/username <target>`, `/phone <number>`, `/info <query>`, `/search <target>`.
- **Security Hardening & Utilities (`src/utils.mjs`)**:
  - `sanitizeInput()`: Protection against command injection, control characters, null bytes, and path traversal across all inputs.
  - Readline history hygiene: Automatic wiping of sensitive credentials and API keys after `/addkey` execution.
  - `maskSensitive()`: Standardized credential masking across all logs and key management tables.
  - `isPhoneLike()`: Cross-platform regex classifier for phone numbers.
- **Developer Experience & CI/CD**:
  - Unit test suite (`tests/report.test.mjs`) covering utils, report generation, file writing, and formatters (17 tests total passing).
  - GitHub Actions CI workflow (`.github/workflows/ci.yml`) running multi-platform node tests and syntax checks.
  - Issue templates for bug reports and feature requests.
  - `npm run lint` script using `node --check`.

### 💅 Changed
- **CLI UI & Aesthetics (`src/ui.mjs`)**:
  - Modernized Braille-based animated spinner (`⣾⣽⣻⢿⡿⣟⣯⣷`) with smooth dynamic color cycling.
  - Redesigned help menu organized into distinct visual sections: OSINT & Threat Intel, DevSecOps Plugins, Session & Workspace, and CLI Flags.
  - Display current version (`v2.0.0`) in banner and help header.
  - Richer color palettes and box borders for tool outputs.

### 🛡️ Fixed
- Quotation escaping and argument parsing stability across PowerShell and Linux shells.
- Error handling in piped STDIN inputs and JSON outputs.

---

## [1.0.0] - 2026-09-18

### 🚀 Added
- Initial release of Gemini Sec Agent.
- Plugin architecture with 9 native DevSecOps & OSINT tools.
- Multi-key rotation and intelligent load-balancing.
- Interactive REPL with Gemini AI integration.
