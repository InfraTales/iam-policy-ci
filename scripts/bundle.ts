import { buildSync } from 'esbuild';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

// Bundles the handler with every dependency inside it, AWS SDK included, so the
// code that runs in Lambda is the code the tests ran. The metafile lets
// test/infra/bundle.test.ts check what went in.
const outdir = join(__dirname, '..', 'build', 'export');
mkdirSync(outdir, { recursive: true });

const result = buildSync({
  entryPoints: [join(__dirname, '..', 'app', 'src', 'export-handler.ts')],
  bundle: true,
  platform: 'node',
  target: 'node24',
  format: 'cjs',
  outfile: join(outdir, 'index.js'),
  minify: true,
  sourcemap: false,
  metafile: true,
  external: [],
  logLevel: 'warning',
});

writeFileSync(join(__dirname, '..', 'build', 'meta.json'), JSON.stringify(result.metafile));
console.log(`bundled ${Object.keys(result.metafile.outputs).join(', ')}`);
