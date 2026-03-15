import { loadChecks } from './checks/index.js';
import { calculateOverallScore } from './scoring.js';
import { loadConfig } from './config.js';

/**
 * Run an array of checks against a context, collect results.
 * Uses Promise.allSettled so one failing check doesn't block others.
 */
export async function runChecks(checks, context, options = {}) {
  const { checkFilter } = options;

  let filtered = checks;
  if (checkFilter) {
    filtered = checks.filter((c) => c.id === checkFilter);
  }

  const settled = await Promise.allSettled(
    filtered.map(async (check) => {
      const result = await check.run(context);
      return {
        id: check.id,
        name: check.name,
        category: check.category,
        weight: check.weight,
        score: result.score,
        findings: result.findings,
      };
    }),
  );

  return settled.map((outcome, i) => {
    if (outcome.status === 'fulfilled') {
      return outcome.value;
    }
    // Check threw — return score 0 with a CRITICAL finding
    const check = filtered[i];
    return {
      id: check.id,
      name: check.name,
      category: check.category,
      weight: check.weight,
      score: 0,
      findings: [
        {
          severity: 'critical',
          title: `Check "${check.id}" failed to run`,
          detail: outcome.reason?.message || 'Unknown error',
        },
      ],
    };
  });
}

/**
 * Full scan: load checks, run them, calculate scores.
 */
export async function scan(options = {}) {
  const checks = await loadChecks();
  const cwd = options.cwd || process.cwd();
  const homedir = options.homedir || (await import('node:os')).homedir();
  const config = await loadConfig(cwd, homedir);

  const context = { cwd, homedir, config };

  const results = await runChecks(checks, context, options);

  // When filtering to specific checks, use average of their scores
  // instead of weighted system (which assumes all checks are present)
  let overallScore;
  if (options.checkFilter) {
    const avg = results.reduce((sum, r) => sum + r.score, 0) / (results.length || 1);
    overallScore = Math.round(avg);
  } else {
    overallScore = calculateOverallScore(results);
  }

  return { score: overallScore, results };
}
