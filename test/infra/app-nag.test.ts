import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Runs infra/bin/app.ts the way the CDK CLI does: context in CDK_CONTEXT_JSON, output in
// CDK_OUTDIR. The validation report names each validation plugin that ran.
function synthBin(context: Record<string, unknown>): string {
  const outdir = mkdtempSync(join(tmpdir(), 'iam-policy-ci-bin-'));
  execFileSync('npx', ['ts-node', '--prefer-ts-exts', 'infra/bin/app.ts'], {
    cwd: join(__dirname, '..', '..'),
    env: { ...process.env, CDK_OUTDIR: outdir, CDK_CONTEXT_JSON: JSON.stringify(context) },
    stdio: 'pipe',
  });
  return outdir;
}

const plugins = (outdir: string): string[] =>
  (JSON.parse(readFileSync(join(outdir, 'validation-report.json'), 'utf8')) as { pluginReports: { pluginName: string }[] }).pluginReports.map(
    (p) => p.pluginName,
  );

test('the app runs cdk-nag by default', () => {
  const out = synthBin({});
  expect(existsSync(join(out, 'IamPolicyCi-Export.template.json'))).toBe(true);
  expect(plugins(out)).toEqual(['AwsSolutions']);
});

test('-c nag=false synthesizes the same stacks without cdk-nag, for the access-analyzer job', () => {
  const out = synthBin({ nag: 'false' });
  expect(existsSync(join(out, 'IamPolicyCi-Export.template.json'))).toBe(true);
  expect(existsSync(join(out, 'IamPolicyCi-CiRole.template.json'))).toBe(true);
  expect(plugins(out)).toEqual([]);
});
