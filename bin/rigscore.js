#!/usr/bin/env node

import { run } from '../src/index.js';

const args = process.argv.slice(2);

if (args.includes('--version')) {
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const pkg = require('../package.json');
  console.log(`rigscore v${pkg.version}`);
  process.exit(0);
}

run(args);
