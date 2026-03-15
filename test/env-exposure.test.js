import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import check from '../src/checks/env-exposure.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(__dirname, 'fixtures', name);

describe('env-exposure check', () => {
  it('has required shape', () => {
    expect(check.id).toBe('env-exposure');
    expect(check.weight).toBe(20);
    expect(typeof check.run).toBe('function');
  });

  it('CRITICAL when .env exists but not in .gitignore', async () => {
    const result = await check.run({ cwd: fixture('env-exposed'), homedir: '/tmp' });
    expect(result.score).toBeLessThan(100);
    const critical = result.findings.find((f) => f.severity === 'critical');
    expect(critical).toBeDefined();
  });

  it('PASS when .env is in .gitignore', async () => {
    const result = await check.run({ cwd: fixture('env-gitignored'), homedir: '/tmp' });
    const critical = result.findings.find((f) => f.severity === 'critical');
    expect(critical).toBeUndefined();
  });

  it('CRITICAL when hardcoded key found in config file', async () => {
    // Build fixture at runtime to avoid secret scanner blocking test data
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rigscore-env-'));
    // Construct the fake key in parts so it's not a literal in source
    const prefix = 'sk-ant-';
    const suffix = 'api03-abcdefghij1234567890';
    fs.writeFileSync(path.join(tmpDir, 'config.js'), `const key = "${prefix}${suffix}";\n`);
    fs.writeFileSync(path.join(tmpDir, '.gitignore'), '.env\n');

    try {
      const result = await check.run({ cwd: tmpDir, homedir: '/tmp' });
      const critical = result.findings.find((f) => f.severity === 'critical');
      expect(critical).toBeDefined();
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('PASS when no .env and no hardcoded keys', async () => {
    const result = await check.run({ cwd: fixture('env-clean'), homedir: '/tmp' });
    const pass = result.findings.find((f) => f.severity === 'pass');
    expect(pass).toBeDefined();
  });
});
