import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// `npm test` runs `npm run bundle` first, so these look at the file Lambda will run.
const root = join(__dirname, '..', '..');
const meta = JSON.parse(readFileSync(join(root, 'build', 'meta.json'), 'utf8')) as {
  inputs: Record<string, unknown>;
  outputs: Record<string, { imports: { path: string; external?: boolean }[] }>;
};

test('the bundle carries its own AWS SDK and imports only Node built-ins', () => {
  const inputs = Object.keys(meta.inputs);
  expect(inputs.some((i) => i.includes('node_modules/@aws-sdk/client-s3/'))).toBe(true);
  expect(inputs.some((i) => i.includes('node_modules/@aws-sdk/lib-dynamodb/'))).toBe(true);
  const external = Object.values(meta.outputs).flatMap((o) => o.imports.filter((i) => i.external).map((i) => i.path));
  for (const path of external) expect(path).toMatch(/^(node:|[a-z_]+$|[a-z_]+\/)/);
  expect(external.some((p) => p.startsWith('@aws-sdk/'))).toBe(false);
});

test('the bundle loads and exports a handler', () => {
   
  const mod = require(join(root, 'build', 'export', 'index.js')) as { handler?: unknown };
  expect(typeof mod.handler).toBe('function');
});
