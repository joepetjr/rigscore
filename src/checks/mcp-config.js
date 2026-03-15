import fs from 'node:fs';
import path from 'node:path';
import { calculateCheckScore } from '../scoring.js';

async function readJsonSafe(p) {
  try {
    const content = await fs.promises.readFile(p, 'utf-8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

const SENSITIVE_ENV_KEYS = [
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_ACCESS_KEY_ID',
  'DATABASE_URL',
  'GITHUB_TOKEN',
  'SLACK_TOKEN',
];

export default {
  id: 'mcp-config',
  name: 'MCP server configuration',
  category: 'supply-chain',
  weight: 25,

  async run(context) {
    const { cwd, homedir } = context;
    const findings = [];

    // Locations to scan for MCP config
    const configPaths = [
      path.join(cwd, '.mcp.json'),
      path.join(cwd, '.vscode', 'mcp.json'),
      path.join(homedir, '.claude', 'claude_desktop_config.json'),
      path.join(homedir, '.cursor', 'mcp.json'),
    ];

    let foundAny = false;

    for (const configPath of configPaths) {
      const config = await readJsonSafe(configPath);
      if (!config) continue;

      foundAny = true;
      const servers = config.mcpServers || {};
      const relPath = path.relative(cwd, configPath) || configPath;

      for (const [name, server] of Object.entries(servers)) {
        // Check transport type
        const transport = server.transport || 'stdio';
        if (transport === 'sse' || transport === 'http' || server.url) {
          findings.push({
            severity: 'warning',
            title: `MCP server "${name}" uses network transport`,
            detail: `Server uses ${transport || 'network'} transport in ${relPath}. Network-based MCP servers have a larger attack surface than stdio.`,
            remediation: 'Prefer stdio transport for local MCP servers. If network transport is required, ensure authentication and TLS.',
            learnMore: 'https://headlessmode.com/blog/mcp-permissions',
          });
        }

        // Check for root filesystem access in args
        const args = server.args || [];
        const argsStr = args.join(' ');
        // Match standalone "/" as an arg (root filesystem access)
        if (args.includes('/') || argsStr.includes(' / ') || argsStr.endsWith(' /')) {
          findings.push({
            severity: 'critical',
            title: `MCP server "${name}" has root filesystem access`,
            detail: `Server can read/write the entire filesystem. Found in ${relPath}.`,
            remediation: 'Scope filesystem access to your project directory only.',
            learnMore: 'https://headlessmode.com/blog/mcp-permissions',
          });
        }

        // Check for sensitive env passthrough
        const env = server.env || {};
        const envKeys = Object.keys(env);
        const sensitiveKeys = envKeys.filter((k) => SENSITIVE_ENV_KEYS.includes(k));
        if (sensitiveKeys.length >= 3) {
          findings.push({
            severity: 'critical',
            title: `MCP server "${name}" receives ${sensitiveKeys.length} sensitive env vars`,
            detail: `Sensitive environment variables (${sensitiveKeys.join(', ')}) are passed to this server.`,
            remediation: 'Only pass environment variables that the server actually needs.',
            learnMore: 'https://headlessmode.com/blog/mcp-permissions',
          });
        } else if (sensitiveKeys.length > 0) {
          findings.push({
            severity: 'warning',
            title: `MCP server "${name}" receives sensitive env var(s): ${sensitiveKeys.join(', ')}`,
            detail: `Sensitive keys passed in ${relPath}.`,
            remediation: 'Verify this server needs these credentials.',
            learnMore: 'https://headlessmode.com/blog/mcp-permissions',
          });
        }

        // Check for unpinned versions
        for (const arg of args) {
          if (arg.includes('@latest')) {
            findings.push({
              severity: 'warning',
              title: `MCP server "${name}" uses unpinned version (@latest)`,
              detail: 'Unpinned versions can introduce breaking changes or supply chain attacks.',
              remediation: 'Pin MCP server packages to specific versions.',
              learnMore: 'https://headlessmode.com/blog/mcp-supply-chain',
            });
            break;
          }
        }

        // Check for inline credentials in args or command
        const fullCommand = [server.command || '', ...args].join(' ');
        const keyPatterns = [/sk-ant-/, /AKIA/, /ghp_/, /xoxb-/];
        for (const pattern of keyPatterns) {
          if (pattern.test(fullCommand)) {
            findings.push({
              severity: 'critical',
              title: `MCP server "${name}" has inline credentials in command`,
              detail: 'API keys or tokens are embedded directly in the MCP server command.',
              remediation: 'Use environment variables instead of inline credentials.',
              learnMore: 'https://headlessmode.com/blog/mcp-permissions',
            });
            break;
          }
        }
      }
    }

    if (!foundAny) {
      findings.push({
        severity: 'info',
        title: 'No MCP configuration found',
        detail: 'No MCP server configuration files detected.',
      });
      return { score: 100, findings };
    }

    if (findings.length === 0) {
      findings.push({
        severity: 'pass',
        title: 'MCP server configuration looks secure',
      });
    }

    return {
      score: calculateCheckScore(findings),
      findings,
    };
  },
};
