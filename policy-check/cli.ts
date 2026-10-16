import { AccessAnalyzerClient } from '@aws-sdk/client-accessanalyzer';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { BILLED_CHECKS, type CheckResult, planChecks, runChecks } from './checks';
import { config as defaultConfig, type PolicyCheckConfig } from './config';
import { extractTemplate, loadAssembly, mergeExtractions } from './extract';

/**
 * Checks every IAM policy in a synthesized CDK app with IAM Access Analyzer.
 *
 *   npx cdk synth && npm run policy-check             # real checks, needs AWS credentials
 *   npm run policy-check -- --dry-run                 # extract and plan only, no AWS calls
 *
 * Exit codes: 0 all checks passed, 1 a check failed, 2 the tool itself failed.
 */

export interface MainDeps {
  client?: AccessAnalyzerClient;
  config?: PolicyCheckConfig;
  log?: (line: string) => void;
  referenceDir?: string;
}

export async function main(argv: string[], deps: MainDeps = {}): Promise<number> {
  const log = deps.log ?? ((line: string) => console.log(line));
  const config = deps.config ?? defaultConfig;
  const { values } = parseArgs({
    args: argv,
    options: {
      assembly: { type: 'string', default: 'cdk.out' },
      'dry-run': { type: 'boolean', default: false },
      region: { type: 'string' },
      report: { type: 'string' },
    },
  });

  let results: CheckResult[];
  let billedCalls: number;
  try {
    const stacks = loadAssembly(values.assembly);
    const extraction = mergeExtractions(stacks.map((s) => extractTemplate(s.stackName, s.template)));
    const { planned, local } = planChecks(extraction, config, deps.referenceDir ?? join(__dirname, 'reference'));
    billedCalls = planned.filter((p) => BILLED_CHECKS.has(p.check)).length;

    log(
      `Found ${extraction.principals.length} principals with identity policies and ` +
        `${extraction.resourcePolicies.length} resource policies in ${stacks.length} stacks.`,
    );
    for (const u of extraction.unchecked) {
      log(`NOT CHECKED ${u.stack}/${u.logicalId} (${u.type}): this tool doesn't read its policy yet`);
    }

    if (values['dry-run']) {
      for (const p of planned) log(`PLAN ${p.check} ${p.target}`);
      log(`Dry run: ${planned.length} API calls planned, ${billedCalls} of them billed custom checks.`);
      results = local;
    } else {
      const region = values.region ?? process.env.AWS_REGION ?? 'us-east-1';
      const client = deps.client ?? new AccessAnalyzerClient({ region });
      results = [...local, ...(await runChecks(client, planned, config))];
    }
  } catch (err) {
    log(`ERROR ${err instanceof Error ? err.message : String(err)}`);
    return 2;
  }

  for (const r of results) {
    log(`${r.status} ${r.check} ${r.target}`);
    for (const m of r.messages) log(`     ${m}`);
  }
  const failed = results.filter((r) => r.status !== 'PASS');
  log(`${results.length - failed.length} passed, ${failed.length} failed, ${billedCalls} billed custom checks.`);
  if (values.report) writeFileSync(values.report, JSON.stringify({ results, billedCalls }, null, 2));
  return failed.length === 0 ? 0 : 1;
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err: unknown) => {
      console.error(err);
      process.exit(2);
    },
  );
}
