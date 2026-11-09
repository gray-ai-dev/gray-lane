// Bundles the boot box helper (main.mjs beside this file, and the workspace code it imports) into one ES module with the
// esbuild workers/package-lock.json pins, as deploy/relay/image/bundle.mjs bundles gray-assistant. build.sh runs it into
// the image's build context (/srv/lane/boot-box.mjs); deploy/tee/e2e/pre-launch-stack.test.mjs runs it to test the same
// bytes pre-launch runs.
//
//   node deploy/tee/boot-box/bundle.mjs <workers directory> <output file>
//
// Deterministic: no timestamps, no absolute paths in the output (esbuild names bundled modules by their path relative to
// the working directory, which this script fixes to the repository root), no source map.
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { chdir } from 'node:process';
import { fileURLToPath } from 'node:url';

const [workersArg, outArg] = process.argv.slice(2);
if (workersArg === undefined || outArg === undefined) {
  console.error('usage: node bundle.mjs <workers directory> <output file>');
  process.exit(2);
}
const workers = resolve(workersArg);
const out = resolve(outArg);
const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(workers, 'package.json'));
const esbuild = require('esbuild');

chdir(resolve(here, '../../..'));
await esbuild.build({
  entryPoints: [join(here, 'main.mjs')],
  outfile: out,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  // CommonJS dependencies call require() for Node's built-ins, which an ES module has no binding for.
  banner: { js: 'import { createRequire as __createRequire } from "node:module"; const require = __createRequire(import.meta.url);' },
  // @gray/json reads JSONC with jsonc-parser, whose `main` is a UMD build whose require() calls esbuild cannot follow;
  // its ES build (its `module`) is the same code (deploy/relay/image/bundle.mjs does the same).
  plugins: [
    {
      name: 'jsonc-parser-esm',
      setup(build) {
        const path = require.resolve('jsonc-parser/lib/esm/main.js');
        build.onResolve({ filter: /^jsonc-parser$/ }, () => ({ path }));
      },
    },
  ],
  legalComments: 'none',
  logLevel: 'warning',
});
