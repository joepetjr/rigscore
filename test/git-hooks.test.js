import { describe, it, expect } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import check from '../src/checks/git-hooks.js';

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'rigscore-git-'));
}

describe('git-hooks check', () => {
  it('has required shape', () => {
    expect(check.id).toBe('git-hooks');
    expect(check.weight).toBe(10);
  });

  it('WARNING when no hooks exist', async () => {
    const tmpDir = makeTmpDir();
    fs.mkdirSync(path.join(tmpDir, '.git', 'hooks'), { recursive: true });
    try {
      const result = await check.run({ cwd: tmpDir, homedir: '/tmp' });
      const warning = result.findings.find((f) => f.severity === 'warning');
      expect(warning).toBeDefined();
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('PASS when pre-commit hook exists', async () => {
    const tmpDir = makeTmpDir();
    const hooksDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
    fs.writeFileSync(path.join(hooksDir, 'pre-commit'), '#!/bin/sh\necho check');
    try {
      const result = await check.run({ cwd: tmpDir, homedir: '/tmp' });
      const pass = result.findings.find((f) => f.severity === 'pass');
      expect(pass).toBeDefined();
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('PASS when husky is installed', async () => {
    const tmpDir = makeTmpDir();
    fs.mkdirSync(path.join(tmpDir, '.git', 'hooks'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, '.husky'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, '.husky', 'pre-commit'), '#!/bin/sh\nnpx lint-staged');
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      devDependencies: { husky: '^9.0.0', 'lint-staged': '^15.0.0' },
    }));
    try {
      const result = await check.run({ cwd: tmpDir, homedir: '/tmp' });
      const pass = result.findings.find((f) => f.severity === 'pass');
      expect(pass).toBeDefined();
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });
});
