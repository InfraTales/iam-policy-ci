import { App, Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CiRoleStack } from '../../infra/lib/ci-role-stack';
import { ExportStack } from '../../infra/lib/export-stack';

export interface Synthesized {
  dir: string;
  exportStack: ExportStack;
  ciStack: CiRoleStack;
  /** cdk-nag violations from the validation report, as "<rule> <construct path>". */
  nagViolations: string[];
}

/**
 * Synthesizes the same two stacks as infra/bin/app.ts into a temp folder.
 * `change` runs before synth, so a test can break the app on purpose.
 */
export function synthApp(change?: (s: { exportStack: ExportStack; ciStack: CiRoleStack }) => void): Synthesized {
  // Same feature flags as `cdk synth`, so tests see the template CI deploys.
  const context = (JSON.parse(readFileSync(join(__dirname, '..', '..', 'cdk.json'), 'utf8')) as { context: Record<string, unknown> }).context;
  const app = new App({ outdir: mkdtempSync(join(tmpdir(), 'iam-policy-ci-')), context });
  const exportStack = new ExportStack(app, 'IamPolicyCi-Export');
  const ciStack = new CiRoleStack(app, 'IamPolicyCi-CiRole', { githubRepo: 'InfraTales/iam-policy-ci' });
  change?.({ exportStack, ciStack });
  Validations.of(app).addPlugins(new AwsSolutionsChecks(app));
  // cdk-nag makes synth throw when it finds something. The report and the templates
  // are written either way, so a test can still look at both.
  try {
    app.synth();
  } catch (err) {
    if (!String(err).includes('ValidationFailed') && !String(err).includes('Validation failed')) throw err;
  }
  const report = JSON.parse(readFileSync(join(app.outdir, 'validation-report.json'), 'utf8')) as {
    pluginReports: { violations: { ruleName: string; violatingConstructs: { constructPath: string }[] }[] }[];
  };
  const nagViolations = report.pluginReports.flatMap((p) =>
    p.violations.flatMap((v) => v.violatingConstructs.map((c) => `${v.ruleName} ${c.constructPath}`)),
  );
  return { dir: app.outdir, exportStack, ciStack, nagViolations };
}
