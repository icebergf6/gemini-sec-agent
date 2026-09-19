import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

/**
 * Lightweight native .env loader without external dependencies
 */
export function loadEnvFile() {
  const envPaths = [
    path.join(rootDir, '.env'),
    path.join(process.cwd(), '.env'),
    path.join(process.env.USERPROFILE || process.env.HOME || '', '.gemini_cli.env')
  ];

  for (const envPath of envPaths) {
    if (fs.existsSync(envPath)) {
      try {
        const content = fs.readFileSync(envPath, 'utf8');
        const lines = content.split(/\r?\n/);
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;
          const eqIdx = trimmed.indexOf('=');
          if (eqIdx > 0) {
            const key = trimmed.substring(0, eqIdx).trim();
            let val = trimmed.substring(eqIdx + 1).trim();
            if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
              val = val.slice(1, -1);
            } else {
              // Strip unquoted inline comments
              const commentIdx = val.indexOf('#');
              if (commentIdx !== -1) {
                val = val.substring(0, commentIdx).trim();
              }
            }
            if (!process.env[key]) {
              process.env[key] = val;
            }
          }
        }
      } catch (err) {
        // Non-fatal error reading .env
      }
    }
  }
}

// Load env on module initialize
loadEnvFile();

/**
 * Key Rotator and Configuration Engine
 */
class KeyManager {
  constructor() {
    this.keys = [];
    this.currentIndex = 0;
    this.refreshKeys();
  }

  refreshKeys() {
    const rawKeys = process.env.GEMINI_API_KEYS || process.env.GEMINI_API_KEY || '';
    this.keys = rawKeys
      .split(/[,;\n]/)
      .map(k => k.trim())
      .filter(k => k.length > 5);
    
    if (this.currentIndex >= this.keys.length) {
      this.currentIndex = 0;
    }
  }

  getActiveKey() {
    if (this.keys.length === 0) {
      this.refreshKeys();
    }
    return this.keys[this.currentIndex] || null;
  }

  rotateKey() {
    if (this.keys.length <= 1) {
      return false;
    }
    const previous = this.currentIndex;
    this.currentIndex = (this.currentIndex + 1) % this.keys.length;
    return true;
  }

  getMaskedKeys() {
    return this.keys.map((key, idx) => {
      const isCurrent = idx === this.currentIndex;
      const prefix = key.slice(0, 7);
      const suffix = key.slice(-4);
      return {
        index: idx + 1,
        masked: key.length > 11 ? `${prefix}...${suffix}` : '***HIDDEN***',
        active: isCurrent
      };
    });
  }

  addKey(newKey) {
    if (newKey && !this.keys.includes(newKey)) {
      this.keys.push(newKey.trim());
      return true;
    }
    return false;
  }
}

export const keyManager = new KeyManager();

export const config = {
  defaultModel: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
  fallbackModels: ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash', 'gemini-1.5-pro'],
  autoRunTools: process.env.AGY_AUTO_RUN_TOOLS !== 'false',
  rootDir,
  pluginsDir: path.join(rootDir, 'plugins'),
  maxToolRecursion: 8,
  timeoutMs: 45000
};

