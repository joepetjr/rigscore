import fs from 'node:fs';
import path from 'node:path';
import { calculateCheckScore } from '../scoring.js';

async function fileExists(p) {
  try {
    await fs.promises.access(p);
    return true;
  } catch {
    return false;
  }
}

async function readJsonSafe(p) {
  try {
    const content = await fs.promises.readFile(p, 'utf-8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

async function readFileSafe(p) {
  try {
    return await fs.promises.readFile(p, 'utf-8');
  } catch {
    return null;
  }
}

export default {
  id: 'git-hooks',
  name: 'Git hooks',
  category: 'process',
  weight: 10,

  async run(context) {
    const { cwd, homedir, config } = context;
    const findings = [];

    const hasGitDir = await fileExists(path.join(cwd, '.git'));
    if (!hasGitDir) {
      findings.push({
        severity: 'info',
        title: 'Not a git repository',
        detail: 'No .git directory found. Git hooks check skipped.',
      });
      return { score: 100, findings };
    }

    let hasHooks = false;

    // Check native git hooks
    const preCommit = path.join(cwd, '.git', 'hooks', 'pre-commit');
    const prePush = path.join(cwd, '.git', 'hooks', 'pre-push');

    if (await fileExists(preCommit)) {
      hasHooks = true;
      findings.push({
        severity: 'pass',
        title: 'Pre-commit hook installed',
      });
    }

    if (await fileExists(prePush)) {
      hasHooks = true;
      findings.push({
        severity: 'pass',
        title: 'Pre-push hook installed',
      });
    }

    // Check husky
    const huskyDir = path.join(cwd, '.husky');
    if (await fileExists(huskyDir)) {
      hasHooks = true;
      findings.push({
        severity: 'pass',
        title: 'Husky hook manager installed',
      });
    }

    // Check lefthook
    const lefthookYml = path.join(cwd, 'lefthook.yml');
    const lefthookYaml = path.join(cwd, 'lefthook.yaml');
    if (await fileExists(lefthookYml) || await fileExists(lefthookYaml)) {
      hasHooks = true;
      findings.push({
        severity: 'pass',
        title: 'Lefthook hook manager configured',
      });
    }

    // Check package.json for husky/lint-staged
    const pkg = await readJsonSafe(path.join(cwd, 'package.json'));
    if (pkg) {
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps.husky || deps['lint-staged']) {
        hasHooks = true;
        // Don't duplicate if husky dir already found
        if (!await fileExists(huskyDir)) {
          findings.push({
            severity: 'pass',
            title: 'Husky/lint-staged in package.json dependencies',
          });
        }
      }
    }

    // Check Claude Code hooks in settings
    const claudeSettingsPaths = [
      path.join(homedir, '.claude', 'settings.json'),
      path.join(cwd, '.claude', 'settings.json'),
    ];
    for (const settingsPath of claudeSettingsPaths) {
      const settings = await readJsonSafe(settingsPath);
      if (settings?.hooks) {
        hasHooks = true;
        findings.push({
          severity: 'pass',
          title: 'Claude Code hooks configured',
          detail: `Hooks found in ${path.relative(cwd, settingsPath) || settingsPath}.`,
        });
        break;
      }
    }

    // Check pushurl guards in .git/config
    const gitConfig = await readFileSafe(path.join(cwd, '.git', 'config'));
    if (gitConfig && /pushurl\s*=\s*no_push/i.test(gitConfig)) {
      hasHooks = true;
      findings.push({
        severity: 'pass',
        title: 'Push URL guard detected in .git/config',
      });
    }

    // Check external hook directories from config
    if (config?.paths?.hookDirs) {
      for (const hookDir of config.paths.hookDirs) {
        if (await fileExists(hookDir)) {
          hasHooks = true;
          findings.push({
            severity: 'pass',
            title: `External hook directory found: ${hookDir}`,
          });
        }
      }
    }

    if (!hasHooks) {
      findings.push({
        severity: 'warning',
        title: 'No pre-commit hooks installed',
        detail: 'Without commit hooks, secrets and governance file changes can be committed unchecked.',
        remediation: 'Install pre-commit hooks with Husky or lefthook to enforce checks before commits.',
        learnMore: 'https://headlessmode.com/blog/git-hooks-for-ai',
      });
    }

    return {
      score: calculateCheckScore(findings),
      findings,
    };
  },
};
