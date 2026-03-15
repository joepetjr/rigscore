import { SEVERITY_MULTIPLIERS, WEIGHTS } from './constants.js';

/**
 * Calculate a check's score (0-100) from its findings.
 * CRITICAL zeros the score, WARNINGs multiply down by 0.5 each.
 */
export function calculateCheckScore(findings) {
  if (findings.length === 0) return 100;

  let multiplier = 1;
  for (const finding of findings) {
    const m = SEVERITY_MULTIPLIERS[finding.severity];
    if (m === undefined) continue;
    multiplier *= m;
  }

  return Math.round(multiplier * 100);
}

/**
 * Calculate overall weighted score from check results.
 * Each result: { id, score }. Weights come from constants.
 */
export function calculateOverallScore(results) {
  let total = 0;
  for (const result of results) {
    const weight = WEIGHTS[result.id] || 0;
    total += (result.score / 100) * weight;
  }
  return Math.round(total);
}
