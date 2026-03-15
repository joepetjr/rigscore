import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import check from '../src/checks/claude-md.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(__dirname, 'fixtures', name);

describe('claude-md check', () => {
  it('has required shape', () => {
    expect(check.id).toBe('claude-md');
    expect(check.weight).toBe(20);
  });

  it('CRITICAL when no CLAUDE.md exists', async () => {
    const result = await check.run({ cwd: fixture('claude-none'), homedir: '/tmp/nonexistent' });
    const critical = result.findings.find((f) => f.severity === 'critical');
    expect(critical).toBeDefined();
  });

  it('WARNING when CLAUDE.md is nearly empty', async () => {
    const result = await check.run({ cwd: fixture('claude-empty'), homedir: '/tmp/nonexistent' });
    const warning = result.findings.find((f) => f.severity === 'warning');
    expect(warning).toBeDefined();
  });

  it('PASS with comprehensive CLAUDE.md', async () => {
    const result = await check.run({ cwd: fixture('claude-full'), homedir: '/tmp/nonexistent' });
    expect(result.score).toBeGreaterThanOrEqual(80);
  });
});
