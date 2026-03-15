import { describe, it, expect } from 'vitest';
import { WEIGHTS, SEVERITY, SEVERITY_MULTIPLIERS } from '../src/constants.js';

describe('constants', () => {
  it('weights sum to 100', () => {
    const total = Object.values(WEIGHTS).reduce((sum, w) => sum + w, 0);
    expect(total).toBe(100);
  });

  it('every severity has a multiplier', () => {
    for (const sev of Object.values(SEVERITY)) {
      expect(SEVERITY_MULTIPLIERS[sev]).toBeDefined();
      expect(typeof SEVERITY_MULTIPLIERS[sev]).toBe('number');
    }
  });

  it('CRITICAL multiplier is 0', () => {
    expect(SEVERITY_MULTIPLIERS[SEVERITY.CRITICAL]).toBe(0);
  });

  it('PASS multiplier is 1', () => {
    expect(SEVERITY_MULTIPLIERS[SEVERITY.PASS]).toBe(1);
  });
});
