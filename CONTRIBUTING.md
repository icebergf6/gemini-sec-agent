# Contributing to Gemini Sec Agent 🛡️

Thank you for your interest in contributing to **Gemini Sec Agent**! We welcome community contributions in the form of bug reports, feature proposals, new security plugins, and documentation improvements.

---

## Code of Conduct
Please be polite, professional, and respectful. Security tools should always be developed and used ethically and in compliance with applicable laws.

---

## Development Setup

1. **Prerequisites**:
   - Node.js 18.0.0 or higher
   - A valid Google Gemini API key ([Google AI Studio](https://aistudio.google.com/))

2. **Clone the repository**:
   ```bash
   git clone https://github.com/icebergf6/gemini-sec-agent.git
   cd gemini-sec-agent
   ```

3. **Install dependencies**:
   ```bash
   npm install
   ```

4. **Set up your environment**:
   Create a `.env` file in the project root:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

5. **Run tests**:
   ```bash
   npm test
   ```

6. **Run linter / syntax validation**:
   ```bash
   npm run lint
   ```

---

## Creating New Security Plugins

Gemini Sec Agent uses an extensible plugin architecture located in `plugins/`.

To build a new plugin:
1. Create a new `.mjs` file in `plugins/your_plugin_name.mjs`.
2. Follow this structure:
   ```javascript
   export const metadata = {
     name: 'your_plugin_name',
     description: 'Describe what your security tool does',
     parameters: {
       target: { type: 'string', required: true, description: 'Target URL or file' }
     }
   };

   export async function execute(params, context) {
     const { target } = params;
     // Implement your security logic here
     return {
       success: true,
       data: {
         target,
         findings: []
       }
     };
   }
   ```
3. Add a corresponding unit test in `tests/`.
4. Ensure `npm test` and `npm run lint` pass.

---

## Submitting a Pull Request (PR)

1. Create a new branch: `git checkout -b feature/your-feature-name`
2. Make your changes adhering to ES Module standards (`.mjs`).
3. Commit with clear semantic commit messages:
   - `feat:` for new features or plugins
   - `fix:` for bug fixes
   - `docs:` for documentation updates
   - `test:` for test additions
4. Push to your fork and submit a PR against `main`.
