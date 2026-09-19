import fs from 'fs/promises';
import path from 'path';
import { pathToFileURL } from 'url';
import { config } from './config.mjs';
import { logWarn, logError } from './ui.mjs';

class PluginLoader {
  constructor() {
    this.plugins = new Map();
  }

  /**
   * Load or reload all plugins from the plugins directory
   */
  async loadPlugins() {
    this.plugins.clear();
    const pluginsDir = config.pluginsDir;

    try {
      await fs.access(pluginsDir);
    } catch {
      // Create directory if it doesn't exist yet
      await fs.mkdir(pluginsDir, { recursive: true });
      return [];
    }

    try {
      const files = await fs.readdir(pluginsDir);
      for (const file of files) {
        if (!file.endsWith('.mjs')) continue;

        const fullPath = path.join(pluginsDir, file);
        const fileUrl = `${pathToFileURL(fullPath).href}?v=${Date.now()}`;

        try {
          const module = await import(fileUrl);
          if (module.declaration && typeof module.execute === 'function') {
            const pluginName = module.declaration.name || path.basename(file, '.mjs');
            this.plugins.set(pluginName, {
              name: pluginName,
              file,
              declaration: module.declaration,
              execute: module.execute,
              description: module.declaration.description || 'No description provided.'
            });
          } else {
            logWarn(`Plugin ${file} dilewati (harus mengekspor 'declaration' dan 'execute')`);
          }
        } catch (err) {
          logError(`Gagal memuat plugin ${file}: ${err.message}`);
        }
      }
    } catch (err) {
      logError(`Gagal membaca folder plugins: ${err.message}`);
    }

    return Array.from(this.plugins.values());
  }

  /**
   * Get all registered plugins
   */
  getAll() {
    return Array.from(this.plugins.values());
  }

  /**
   * Get plugin by name
   */
  get(name) {
    return this.plugins.get(name);
  }

  /**
   * Transform plugin declarations into Gemini FunctionDeclaration format
   */
  getGeminiTools() {
    const functionDeclarations = [];

    for (const plugin of this.plugins.values()) {
      const decl = plugin.declaration;
      functionDeclarations.push({
        name: decl.name,
        description: decl.description,
        parameters: decl.parameters || {
          type: 'object',
          properties: {},
          required: []
        }
      });
    }

    if (functionDeclarations.length === 0) {
      return [];
    }

    return [{ functionDeclarations }];
  }

  /**
   * Safely execute a plugin with argument validation and error wrapping
   */
  async execute(name, args = {}) {
    const plugin = this.plugins.get(name);
    if (!plugin) {
      return {
        success: false,
        error: `Plugin '${name}' tidak ditemukan di sistem.`
      };
    }

    try {
      const startTime = Date.now();
      const result = await plugin.execute(args);
      const durationMs = Date.now() - startTime;

      if (result && typeof result === 'object' && result.success === false) {
        return {
          success: false,
          durationMs,
          error: result.error || `Eksekusi plugin '${name}' gagal.`
        };
      }

      return {
        success: true,
        durationMs,
        data: result
      };
    } catch (err) {
      return {
        success: false,
        error: `Eksekusi plugin '${name}' gagal: ${err.message}`,
        stack: err.stack
      };
    }
  }
}

export const pluginLoader = new PluginLoader();
