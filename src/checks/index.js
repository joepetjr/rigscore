import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Auto-discover all check modules in this directory (excluding index.js).
 */
export async function loadChecks() {
  const files = await fs.promises.readdir(__dirname);
  const checkFiles = files.filter(
    (f) => f.endsWith('.js') && f !== 'index.js',
  );

  const checks = [];
  for (const file of checkFiles) {
    const mod = await import(path.join(__dirname, file));
    checks.push(mod.default);
  }
  return checks;
}
