import fs from 'node:fs';
import path from 'node:path';
import { calculateCheckScore } from '../scoring.js';

async function readFileSafe(p) {
  try {
    return await fs.promises.readFile(p, 'utf-8');
  } catch {
    return null;
  }
}

const QUALITY_CHECKS = [
  {
    name: 'forbidden actions',
    pattern: /\b(never|forbidden|must not|do not|prohibited)\b/i,
    points: 4,
  },
  {
    name: 'approval gates',
    pattern: /\b(approv(al|e)|human.in.the.loop|confirm|permission)\b/i,
    points: 4,
  },
  {
    name: 'path restrictions',
    pattern: /\b(restrict|allowed?.?(path|dir)|boundar|working.?dir)/i,
    points: 3,
  },
  {
    name: 'network restrictions',
    pattern: /\b(no external|network|api.?access|external.?(call|request|fetch))/i,
    points: 3,
  },
  {
    name: 'anti-injection',
    pattern: /\b(ignore previous|prompt.?injection|instruction.?override|injection)\b/i,
    points: 3,
  },
];

const LENGTH_THRESHOLD = 50;

export default {
  id: 'claude-md',
  name: 'CLAUDE.md governance',
  category: 'governance',
  weight: 20,

  async run(context) {
    const { cwd, homedir } = context;
    const findings = [];

    // Check project-level CLAUDE.md
    const projectPath = path.join(cwd, 'CLAUDE.md');
    const globalPath = path.join(homedir, '.claude', 'CLAUDE.md');

    const projectContent = await readFileSafe(projectPath);
    const globalContent = await readFileSafe(globalPath);

    const content = projectContent || globalContent;

    if (!content) {
      findings.push({
        severity: 'critical',
        title: 'No CLAUDE.md found',
        detail: 'Without a CLAUDE.md governance file, AI agents operate without explicit boundaries or rules.',
        remediation: 'Create a CLAUDE.md with execution boundaries, forbidden actions, and approval gates.',
        learnMore: 'https://headlessmode.com/blog/why-claude-md-matters',
      });
      return { score: calculateCheckScore(findings), findings };
    }

    const lines = content.split('\n');

    // Check content length
    if (lines.length < LENGTH_THRESHOLD) {
      findings.push({
        severity: 'warning',
        title: 'CLAUDE.md is short (under 50 lines)',
        detail: 'A short governance file may not provide sufficient boundaries for AI agent behavior.',
        remediation: 'Add forbidden actions, approval gates, path restrictions, and anti-injection rules.',
        learnMore: 'https://headlessmode.com/blog/why-claude-md-matters',
      });
    }

    // Check quality patterns
    let qualityScore = 0;
    for (const check of QUALITY_CHECKS) {
      if (check.pattern.test(content)) {
        qualityScore += check.points;
      } else {
        findings.push({
          severity: 'warning',
          title: `CLAUDE.md missing: ${check.name}`,
          detail: `No ${check.name} rules detected in your governance file.`,
          remediation: `Add ${check.name} instructions to your CLAUDE.md.`,
          learnMore: 'https://headlessmode.com/blog/claude-md-hardening',
        });
      }
    }

    if (findings.length === 0) {
      findings.push({
        severity: 'pass',
        title: 'CLAUDE.md contains comprehensive governance rules',
      });
    }

    return {
      score: calculateCheckScore(findings),
      findings,
    };
  },
};
