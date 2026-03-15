import fs from 'node:fs';
import path from 'node:path';
import { calculateCheckScore } from '../scoring.js';

const KEY_PATTERNS = [
  /sk-ant-[a-zA-Z0-9_-]{10,}/,         // Anthropic
  /AKIA[0-9A-Z]{16}/,                   // AWS access key
  /ghp_[a-zA-Z0-9]{36}/,               // GitHub PAT
  /gho_[a-zA-Z0-9]{36}/,               // GitHub OAuth
  /xoxb-[a-zA-Z0-9-]+/,               // Slack bot token
  /xoxp-[a-zA-Z0-9-]+/,               // Slack user token
  /sk-[a-zA-Z0-9]{20,}/,               // OpenAI-style
  /glpat-[a-zA-Z0-9_-]{20,}/,          // GitLab PAT
];

const CONFIG_FILES = [
  'CLAUDE.md',
  '.claude/settings.json',
  '.mcp.json',
  '.cursorrules',
  '.windsurfrules',
  'copilot-instructions.md',
  'config.js',
  'config.ts',
  'config.json',
];

async function fileExists(p) {
  try {
    await fs.promises.access(p);
    return true;
  } catch {
    return false;
  }
}

async function readFileSafe(p) {
  try {
    return await fs.promises.readFile(p, 'utf-8');
  } catch {
    return null;
  }
}

async function statSafe(p) {
  try {
    return await fs.promises.stat(p);
  } catch {
    return null;
  }
}

async function isInGitignore(cwd) {
  const gitignorePath = path.join(cwd, '.gitignore');
  const content = await readFileSafe(gitignorePath);
  if (!content) return false;
  const lines = content.split('\n').map((l) => l.trim());
  return lines.some((l) => l === '.env' || l === '.env*' || l === '*.env');
}

export default {
  id: 'env-exposure',
  name: 'Secret exposure',
  category: 'secrets',
  weight: 20,

  async run(context) {
    const { cwd } = context;
    const findings = [];

    // Check for .env files
    const envFiles = [];
    const entries = await fs.promises.readdir(cwd).catch(() => []);
    for (const entry of entries) {
      if (entry === '.env' || (entry.startsWith('.env.') && !entry.endsWith('.example'))) {
        envFiles.push(entry);
      }
    }

    if (envFiles.length > 0) {
      const ignored = await isInGitignore(cwd);
      if (!ignored) {
        findings.push({
          severity: 'critical',
          title: '.env file found but NOT in .gitignore',
          detail: 'Your API keys and secrets will be committed to version control.',
          remediation: 'Add .env to .gitignore immediately.',
          learnMore: 'https://headlessmode.com/blog/env-security',
        });
      } else {
        findings.push({
          severity: 'pass',
          title: '.env file properly gitignored',
        });
      }

      // Check .env file permissions (Linux only)
      if (process.platform !== 'win32') {
        for (const envFile of envFiles) {
          const envStat = await statSafe(path.join(cwd, envFile));
          if (envStat) {
            const mode = envStat.mode & 0o777;
            // World-readable check: "others" read bit
            if (mode & 0o004) {
              findings.push({
                severity: 'warning',
                title: `${envFile} is world-readable`,
                detail: `${envFile} has mode ${mode.toString(8)}. Secrets files should not be world-readable.`,
                remediation: `Run: chmod 600 ${envFile}`,
              });
            }
          }
        }
      }
    }

    // Detect SOPS
    const sopsConfig = await fileExists(path.join(cwd, '.sops.yaml'));
    if (sopsConfig) {
      findings.push({
        severity: 'pass',
        title: 'Secrets managed by SOPS',
        detail: '.sops.yaml found — secrets are encrypted at rest.',
      });
    }

    // Scan config files for hardcoded keys
    let hardcodedFound = false;
    for (const configFile of CONFIG_FILES) {
      const filePath = path.join(cwd, configFile);
      const content = await readFileSafe(filePath);
      if (!content) continue;

      for (const pattern of KEY_PATTERNS) {
        if (pattern.test(content)) {
          hardcodedFound = true;
          findings.push({
            severity: 'critical',
            title: `Hardcoded API key found in ${configFile}`,
            detail: `A secret matching pattern ${pattern.source.slice(0, 20)}... was found in ${configFile}.`,
            remediation: 'Move secrets to .env and reference via environment variables.',
            learnMore: 'https://headlessmode.com/blog/env-security',
          });
          break; // one finding per file
        }
      }
    }

    if (envFiles.length === 0 && !hardcodedFound && !sopsConfig) {
      findings.push({
        severity: 'pass',
        title: 'No exposed secrets detected',
      });
    }

    return {
      score: calculateCheckScore(findings),
      findings,
    };
  },
};
