import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import check from '../src/checks/skill-files.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(__dirname, 'fixtures', name);

describe('skill-files check', () => {
  it('has required shape', () => {
    expect(check.id).toBe('skill-files');
    expect(check.weight).toBe(10);
  });

  it('CRITICAL when injection pattern found', async () => {
    const result = await check.run({ cwd: fixture('skill-injection'), homedir: '/tmp' });
    const critical = result.findings.find((f) => f.severity === 'critical');
    expect(critical).toBeDefined();
  });

  it('WARNING when external URLs found', async () => {
    const result = await check.run({ cwd: fixture('skill-urls'), homedir: '/tmp' });
    const warning = result.findings.find((f) => f.severity === 'warning');
    expect(warning).toBeDefined();
  });

  it('PASS when skill files are clean', async () => {
    const result = await check.run({ cwd: fixture('skill-clean'), homedir: '/tmp' });
    const critical = result.findings.find((f) => f.severity === 'critical');
    expect(critical).toBeUndefined();
  });

  it('INFO when no skill files found', async () => {
    const result = await check.run({ cwd: fixture('skill-none'), homedir: '/tmp' });
    expect(result.score).toBe(100);
  });
});
