# rigscore

**A security score for your AI development environment.**

One command. 6 checks. A score out of 100. Know where you stand before something breaks.

```bash
npx rigscore
```

```
  ╭────────────────────────────────────────╮
  │                                        │
  │        rigscore v0.1.0                 │
  │   AI Dev Environment Security Scan     │
  │                                        │
  ╰────────────────────────────────────────╯

  Scanning /home/user/my-project ...

  ✗ CLAUDE.md governance.......... 0/20
  ✓ Docker security............... 15/15
  ✓ Secret exposure............... 20/20
  ✗ Git hooks..................... 5/10
  ✓ MCP server configuration...... 25/25
  ✓ Skill file safety............. 10/10

  ╭────────────────────────────────────────╮
  │                                        │
  │         YOUR RIGSCORE: 75/100          │
  │         Grade: B                       │
  │                                        │
  ╰────────────────────────────────────────╯

  CRITICAL (1)
  ✗ No CLAUDE.md found
    → Without a CLAUDE.md governance file, AI agents operate
      without explicit boundaries or rules.

  WARNING (1)
  ⚠ No pre-commit hooks installed
    → Without commit hooks, secrets and governance file changes
      can be committed unchecked.
```

## Why this exists

AI coding tools are powerful. Claude Code, Cursor, Windsurf, and autonomous agents can read your filesystem, execute commands, call APIs, and modify your codebase. Most developers set them up fast and never audit the security posture.

rigscore checks the things that matter:

- Does your AI agent have governance rules, or is it operating without boundaries?
- Are your MCP servers scoped to project directories, or can they access your entire filesystem?
- Are your API keys in `.gitignore`, or one commit away from being public?
- Is Docker configured safely, or is the socket exposed?
- Do you have commit hooks catching mistakes, or is everything going straight to the repo?
- Are your skill files clean, or could they contain injection payloads?

Run it. See the score. Fix what's broken.

## Install and run

No setup. No accounts. No data leaves your machine.

```bash
# Run on the current directory
npx rigscore

# Run on a specific project
npx rigscore /path/to/project

# Output as JSON (for CI integration)
npx rigscore --json

# Generate a README badge
npx rigscore --badge
```

## What it checks

### 1. CLAUDE.md governance (20 points) {#why-claude-md-matters}

Your CLAUDE.md file tells AI agents what they can and can't do. Without one, your agent operates with no explicit rules — it can access any file, run any command, and make any API call that its underlying permissions allow.

**What rigscore looks for:**
- Does a CLAUDE.md exist in the project root or `~/.claude/`?
- Does it contain forbidden action rules?
- Does it have human-in-the-loop approval gates?
- Does it restrict file and directory access?
- Does it restrict network and API access?
- Does it include anti-injection instructions?

**A good CLAUDE.md is not a wishlist.** It's mechanical enforcement. "Don't do X" is behavioral — the agent might ignore it. File permissions, hook scripts, and gated approvals are mechanical — they work regardless of what the agent tries. {#claude-md-hardening}

**What to fix:** Create a CLAUDE.md with explicit execution boundaries, forbidden actions, file access restrictions, and approval gates. Be specific — "don't access sensitive files" is too vague. List the exact directories and operations that are off-limits.

### 2. MCP server configuration (25 points) {#mcp-permissions}

[MCP (Model Context Protocol)](https://modelcontextprotocol.io/) lets AI agents connect to external tools via servers. Each server exposes capabilities — filesystem access, API calls, database queries. The security risk is in the permissions.

**What rigscore looks for:**
- Transport type: `stdio` (local, safer) vs. `sse` (network, riskier)
- Wildcard environment passthrough (`env: {...process.env}`) — exposes all your env vars to the server
- Filesystem scope: is the server limited to project directories, or does it have access to `/`?
- Version pinning: are packages locked to specific versions, or using `@latest`?

**The problem is widespread.** A [recent security audit](https://dev.to/kai_security_ai/i-scanned-every-server-in-the-official-mcp-registry-heres-what-i-found-4p4m) found that 41% of the 518 servers in the official MCP registry have no authentication at the protocol level.

**Supply chain risk:** An MCP server installed as `@latest` today could push a malicious update tomorrow. Version pinning prevents this. {#mcp-supply-chain}

**What to fix:** Scope filesystem servers to your project directory only. Remove wildcard env passthrough — pass only the specific variables each server needs. Pin all server packages to exact versions. Prefer `stdio` transport unless you specifically need network access.

### 3. Secret exposure (20 points) {#env-security}

API keys, tokens, and credentials in the wrong places are the most common security failure in any codebase — and AI development makes it worse because agents read config files, skill files, and environment variables as part of their normal operation.

**What rigscore looks for:**
- `.env` files present but not in `.gitignore`
- API key patterns in config files, CLAUDE.md, skill files, or MCP configs (patterns: `sk-`, `AKIA`, `key-`, common token formats)
- `.env` file permissions (world-readable vs. user-only)
- API keys in shell history (`.bash_history`, `.zsh_history`)

**What to fix:** Add `.env` to `.gitignore` immediately. Set `.env` permissions to `600` (user read/write only). Never hardcode API keys in governance or config files. Use environment variables and pass them explicitly.

### 4. Docker security (15 points) {#docker-isolation}

Docker containers provide isolation for AI agent workloads — but misconfigured containers can actually increase your attack surface instead of reducing it.

**What rigscore looks for:**
- Docker socket (`/var/run/docker.sock`) mounted in containers — this is a container escape vector {#docker-socket-risk}
- `privileged: true` in docker-compose — gives the container full host access
- Volume mounts to sensitive host directories (`/`, `/etc`, `/root`, `~/.ssh`)
- Host network mode — bypasses container network isolation

**What to fix:** Never mount the Docker socket unless absolutely necessary. Never run containers in privileged mode. Scope volume mounts to project directories only. Use Docker's default bridge networking, not host mode.

### 5. Git hooks (10 points) {#git-hooks-for-ai}

Git hooks are your last line of defense before code leaves your machine. Without pre-commit hooks, secrets, broken governance files, and unreviewed changes go straight to the repo.

**What rigscore looks for:**
- Pre-commit hooks present (`.git/hooks/pre-commit` or a hook manager like Husky/lefthook)
- Secret scanning in commit hooks
- Hook manager configuration (`.husky/`, `.lefthook.yml`)

**What to fix:** Install [Husky](https://github.com/typicode/husky) or [lefthook](https://github.com/evilmartians/lefthook) and add pre-commit hooks that scan for secret patterns and validate governance files.

### 6. Skill file safety (10 points) {#skill-file-injection}

Skill files (`.cursorrules`, `.windsurfrules`, `copilot-instructions.md`, files in `.claude/skills/`) tell AI agents how to behave. They're also a prompt injection vector — malicious instructions embedded in skill files can override agent behavior.

**What rigscore looks for:**
- Instruction override patterns ("ignore previous instructions", "disregard", "new system prompt")
- Shell execution instructions embedded in skill files
- External URL references (potential data exfiltration)
- Base64 or encoded content (obfuscated payloads)
- File permissions (writable by others?)

**What to fix:** Audit all skill files for unexpected instructions. Lock file permissions so only you can modify them. Be cautious with skill files from untrusted sources — treat them like executable code, because that's effectively what they are.

## Scoring

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100 | A | Strong security posture |
| 75-89 | B | Good foundation, some gaps |
| 60-74 | C | Moderate risk, needs attention |
| 40-59 | D | Significant gaps |
| 0-39 | F | Critical issues, fix immediately |

Each CRITICAL finding zeroes out its sub-check. Each WARNING reduces it by 50%. INFO findings don't affect the score.

## Options

```bash
npx rigscore                     # Scan current directory
npx rigscore /path/to/project    # Scan a specific project
npx rigscore --json              # JSON output for CI/scripting
npx rigscore --badge             # Generate a markdown badge for your README
npx rigscore --no-color          # Plain text output
npx rigscore --version           # Version info
```

## Privacy

rigscore runs entirely on your local machine. No data is collected, transmitted, or stored anywhere. No API calls. No telemetry. No accounts. The scan reads your local config files and outputs results to your terminal. That's it.

## Contributing

Issues and PRs welcome. If you find a check that's missing or a false positive, [open an issue](https://github.com/backroadcreative/rigscore/issues).

### Adding a check

Each check is a module in `src/checks/` that exports a standard interface:

```javascript
export default {
  id: 'my-check',
  name: 'My new check',
  category: 'governance',  // governance | secrets | isolation | supply-chain
  weight: 10,              // max points this check contributes

  async run(context) {
    // context.cwd = working directory
    // context.homedir = user home directory
    return {
      score: 0-100,
      findings: [{
        severity: 'critical', // critical | warning | info | pass
        title: 'What was found',
        detail: 'Why it matters',
        remediation: 'How to fix it',
        learnMore: 'https://...'
      }]
    }
  }
}
```

## License

MIT

## Author

Built by [Joe Petrucelli](https://headlessmode.com) — technologist, AI agent security, 25 years building and securing enterprise systems.
