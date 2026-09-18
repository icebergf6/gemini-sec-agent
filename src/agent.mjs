import { GoogleGenAI } from '@google/genai';
import { keyManager, config } from './config.mjs';
import { pluginLoader } from './plugin_loader.mjs';
import { logWarn, logError, logToolCall } from './ui.mjs';

class GeminiAgent {
  constructor() {
    this.currentModel = config.defaultModel;
    this.chatSession = null;
    this.aiClient = null;
    this.systemInstruction = `
You are AGY (AntiGravity AI) operating in OVERPOWER CLI ARCHITECT & CYBERSECURITY OPERATOR mode.
You are an advanced terminal security workstation and DevSecOps agent.
You have direct access to tools/plugins for:
- Web & HTTP security header/SSL auditing (web_audit)
- High-speed TCP port and service scanning (port_scanner)
- Deep credential/secret and API token scanning (secret_scanner)
- Dockerfile & Docker Compose IaC security linting (iac_linter)
- SOC log parsing & threat hunting (log_hunter)
- Package dependency CVE & supply-chain auditing (dep_audit)
- Cross-platform OS & system security posture checks (sys_ops)
- Automated surgical code patching with backup verification (code_patcher)
- Social media username & phone number OSINT reconnaissance (osint_search)

DIRECTIVES:
1. Always analyze findings with security engineering rigor (severity: CRITICAL, HIGH, MEDIUM, LOW, INFO).
2. When asked to audit, check, or inspect system/target/files, utilize your available tools actively.
3. Provide actionable remediation snippets and root-cause explanations.
4. Keep terminal formatting crisp, concise, and structured.
`.trim();
  }

  setModel(modelName) {
    if (modelName && typeof modelName === 'string') {
      this.currentModel = modelName.trim();
      this.initSession();
      return true;
    }
    return false;
  }

  getModel() {
    return this.currentModel;
  }

  getClient() {
    const activeKey = keyManager.getActiveKey();
    if (!activeKey) {
      throw new Error(
        'Tidak ada Gemini API Key yang ditemukan!\n' +
        'Silakan set GEMINI_API_KEY di environment variable atau buat file .env di folder project.'
      );
    }
    return new GoogleGenAI({ apiKey: activeKey });
  }

  initSession() {
    try {
      this.aiClient = this.getClient();
      const tools = pluginLoader.getGeminiTools();

      const chatConfig = {
        systemInstruction: this.systemInstruction
      };

      if (tools.length > 0) {
        chatConfig.tools = tools;
      }

      this.chatSession = this.aiClient.chats.create({
        model: this.currentModel,
        config: chatConfig
      });

      return true;
    } catch (err) {
      logError(`Inisialisasi sesi Gemini gagal: ${err.message}`);
      return false;
    }
  }

  /**
   * Execute chat completion with recursive tool-calling loop and key rotation
   */
  async sendMessage(prompt, onProgress = null) {
    if (!this.chatSession) {
      this.initSession();
    }

    let retryCount = 0;
    const maxRetries = Math.max(keyManager.keys.length * 2, 3);

    while (retryCount <= maxRetries) {
      try {
        return await this.executeChatLoop({ message: prompt }, onProgress);
      } catch (err) {
        const isRateLimit =
          err.status === 429 ||
          (err.message && err.message.includes('429')) ||
          (err.message && err.message.includes('RESOURCE_EXHAUSTED')) ||
          (err.message && err.message.includes('Quota'));

        const isNotFound =
          err.status === 404 ||
          (err.message && err.message.includes('404')) ||
          (err.message && err.message.includes('no longer available')) ||
          (err.message && err.message.includes('not found'));

        if (isRateLimit && keyManager.rotateKey()) {
          logWarn(`Rate limit tercapai. Rotasi ke API Key berikutnya (Percobaan ${retryCount + 1}/${maxRetries})...`);
          this.initSession();
          retryCount++;
          await new Promise(res => setTimeout(res, 1000 * retryCount));
          continue;
        }

        if (isNotFound) {
          const nextModel = config.fallbackModels.find(m => m !== this.currentModel);
          if (nextModel) {
            logWarn(`Model '${this.currentModel}' tidak tersedia (404). Mengalihkan ke model cadangan: ${nextModel}...`);
            this.currentModel = nextModel;
            this.initSession();
            retryCount++;
            continue;
          }
        }

        throw err;
      }
    }

    throw new Error('Gagal memproses pesan setelah mencoba semua opsi rotasi.');
  }

  /**
   * Internal recursive function-calling loop using @google/genai
   */
  async executeChatLoop(messagePayload, onProgress = null, depth = 0) {
    if (depth > config.maxToolRecursion) {
      return 'Batas maksimum pemanggilan alat (tool recursion limit) tercapai.';
    }

    const response = await this.chatSession.sendMessage(messagePayload);

    // Check if Gemini requested tool execution
    const functionCalls = response.functionCalls;

    if (!functionCalls || functionCalls.length === 0) {
      return response.text;
    }

    // Execute each requested tool
    const functionResponses = [];

    for (const call of functionCalls) {
      const toolName = call.name;
      const toolArgs = call.args || {};

      logToolCall(toolName, toolArgs);
      if (onProgress) {
        onProgress(`Menjalankan plugin: ${toolName}...`);
      }

      const executionResult = await pluginLoader.execute(toolName, toolArgs);

      functionResponses.push({
        functionResponse: {
          name: toolName,
          response: {
            output: executionResult.success ? executionResult.data : { error: executionResult.error }
          }
        }
      });
    }

    // Send tool output back to Gemini to synthesize response
    return await this.executeChatLoop({ message: functionResponses }, onProgress, depth + 1);
  }
}

export const agent = new GeminiAgent();
