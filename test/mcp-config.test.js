import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import check from '../src/checks/mcp-config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => path.join(__dirname, 'fixtures', name);

describe('mcp-config check', () => {
  it('has required shape', () => {
    expect(check.id).toBe('mcp-config');
    expect(check.weight).toBe(15);
  });

  it('PASS with clean stdio config', async () => {
    const result = await check.run({ cwd: fixture('mcp-clean'), homedir: '/tmp/nonexistent' });
    const critical = result.findings.find((f) => f.severity === 'critical');
    expect(critical).toBeUndefined();
  });

  it('CRITICAL when root filesystem access', async () => {
    const result = await check.run({ cwd: fixture('mcp-root'), homedir: '/tmp/nonexistent' });
    const critical = result.findings.find((f) => f.severity === 'critical');
    expect(critical).toBeDefined();
    expect(critical.title).toMatch(/root|filesystem/i);
  });

  it('CRITICAL/WARNING for env passthrough and SSE transport', async () => {
    const result = await check.run({ cwd: fixture('mcp-passthrough'), homedir: '/tmp/nonexistent' });
    // Should flag SSE transport and broad env passthrough
    const issues = result.findings.filter((f) => f.severity === 'critical' || f.severity === 'warning');
    expect(issues.length).toBeGreaterThanOrEqual(1);
  });

  it('INFO when no MCP config found', async () => {
    const result = await check.run({ cwd: fixture('mcp-none'), homedir: '/tmp/nonexistent' });
    const info = result.findings.find((f) => f.severity === 'info');
    expect(info).toBeDefined();
    expect(result.score).toBe(100);
  });
});
