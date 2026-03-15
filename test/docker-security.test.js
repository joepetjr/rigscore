import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import check from '../src/checks/docker-security.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(__dirname, 'fixtures', name);

describe('docker-security check', () => {
  it('has required shape', () => {
    expect(check.id).toBe('docker-security');
    expect(check.weight).toBe(15);
  });

  it('CRITICAL when socket mounted and privileged', async () => {
    const result = await check.run({ cwd: fixture('docker-socket'), homedir: '/tmp' });
    const criticals = result.findings.filter((f) => f.severity === 'critical');
    expect(criticals.length).toBeGreaterThanOrEqual(2);
  });

  it('PASS with proper isolation', async () => {
    const result = await check.run({ cwd: fixture('docker-clean'), homedir: '/tmp' });
    const critical = result.findings.find((f) => f.severity === 'critical');
    expect(critical).toBeUndefined();
    expect(result.score).toBeGreaterThanOrEqual(80);
  });

  it('INFO when no Docker files', async () => {
    const result = await check.run({ cwd: fixture('docker-none'), homedir: '/tmp' });
    const info = result.findings.find((f) => f.severity === 'info');
    expect(info).toBeDefined();
    expect(result.score).toBe(100);
  });
});
