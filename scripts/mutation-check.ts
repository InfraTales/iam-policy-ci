// Breaks each safeguard on purpose, one at a time, and checks that a test fails.
// A mutant that survives means a test is missing or wrong, not the code.
//
//   npm run mutate                                          # unit, policy and infra mutants
//   AWS_ENDPOINT_URL_DYNAMODB=http://localhost:8000 npm run mutate   # plus the DynamoDB Local one
//
// CI runs it in the dynamodb-local job, so every mutant runs there. Run `npm run bundle` first.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

interface Mutant {
  name: string;
  file: string;
  from: string;
  to: string;
  /** Jest test files (jest.config.js) that should catch it. */
  tests?: string[];
  /** DynamoDB Local test files (jest.integration.config.js). */
  int?: string[];
}

const CLI = 'test/policy/cli.test.ts';
const STACKS = 'test/infra/stacks.test.ts';

const mutants: Mutant[] = [
  {
    name: 'a check answer with no result counts as PASS',
    file: 'policy-check/checks.ts',
    from: "          resourceType: c.resourceType as AccessCheckResourceType,\n        }),\n      );\n      return {\n        check: c.check,\n        target: c.target,\n        status: out.result === 'PASS' ? 'PASS' : 'FAIL',",
    to: "          resourceType: c.resourceType as AccessCheckResourceType,\n        }),\n      );\n      return {\n        check: c.check,\n        target: c.target,\n        status: out.result !== 'FAIL' ? 'PASS' : 'FAIL',",
    tests: [CLI],
  },
  { name: 'SECURITY_WARNING no longer blocks', file: 'policy-check/checks.ts', from: "const BLOCKING_FINDINGS = new Set(['ERROR', 'SECURITY_WARNING']);", to: "const BLOCKING_FINDINGS = new Set(['ERROR']);", tests: [CLI] },
  {
    name: 'an unknown Fn:: passes through unresolved',
    file: 'policy-check/resolve.ts',
    from: '        if (key.startsWith(\'Fn::\')) {\n          throw new UnresolvableError(',
    to: '        if (key.startsWith(\'Fn::NeverMatches\')) {\n          throw new UnresolvableError(',
    tests: ['test/unit/resolve.test.ts'],
  },
  {
    name: 'a policy on a role outside the template is skipped',
    file: 'policy-check/extract.ts',
    from: "      throw new UnresolvableError(`${where} attaches to ${logicalId}, which isn't a role, user or group in ${stackName}`);",
    to: '      return { stack: stackName, logicalId, type: \'role\', sources: [], externalManagedPolicyArns: [], merged: { Statement: [] } } as unknown as PrincipalPolicies;',
    tests: ['test/unit/extract.test.ts'],
  },
  { name: 'ValidatePolicy ignores nextToken', file: 'policy-check/checks.ts', from: 'nextToken = page.nextToken;', to: 'nextToken = undefined;', tests: [CLI] },
  { name: 'a role with no reference policy passes', file: 'policy-check/checks.ts', from: '    if (!rule) {\n      local.push({\n        check: \'ReferenceExists\',\n        target,\n        status: \'FAIL\',', to: '    if (!rule) {\n      local.push({\n        check: \'ReferenceExists\',\n        target,\n        status: \'PASS\',', tests: [CLI] },
  { name: 'the managed policy allow list is ignored', file: 'policy-check/checks.ts', from: "status: unknownManaged.length === 0 ? 'PASS' : 'FAIL',", to: "status: 'PASS',", tests: [CLI] },
  { name: 'never-grant actions not split at 100', file: 'policy-check/checks.ts', from: 'i += MAX_ACTIONS_PER_CALL) {', to: 'i += 1000) {', tests: [CLI] },
  { name: 'the offline action check lets any action through', file: 'policy-check/checks.ts', from: 'if (!allowed.some((g) => g.test(action))) out.push(', to: 'if (allowed.length === 0) out.push(', tests: [CLI, 'test/unit/actions-in-reference.test.ts'] },
  {
    name: 'the role gains s3:DeleteObject, which the code never calls',
    file: 'infra/lib/export-stack.ts',
    from: "actions: ['s3:PutObject'],",
    to: "actions: ['s3:PutObject', 's3:DeleteObject'],",
    tests: ['test/policy/actions-used.test.ts'],
  },
  {
    name: 'the CI trust policy loses its sub condition',
    file: 'infra/lib/ci-role-stack.ts',
    from: "        StringLike: {\n          'token.actions.githubusercontent.com:sub': [",
    to: "        StringLikeX: {\n          'token.actions.githubusercontent.com:sub': [",
    tests: [STACKS],
  },
  {
    name: 'the function role attaches AWSLambdaBasicExecutionRole',
    file: 'infra/lib/export-stack.ts',
    from: "      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),\n      description: 'Export function:",
    to: "      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),\n      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')],\n      description: 'Export function:",
    tests: [STACKS],
  },
  { name: 'the bucket loses enforceSSL', file: 'infra/lib/export-stack.ts', from: 'enforceSSL: true,', to: 'enforceSSL: false,', tests: [STACKS] },
  { name: 'the handler accepts any day value', file: 'app/src/export-handler.ts', from: "if (typeof event?.day !== 'string' || !DAY.test(event.day)) {", to: "if (typeof event?.day !== 'string') {", tests: ['test/unit/handler.test.ts'] },
  { name: 'the handler reads only the first Query page', file: 'app/src/export-handler.ts', from: '  } while (startKey !== undefined);', to: '  } while (false);', int: ['test/int/export.int.test.ts'] },
];

const root = join(__dirname, '..');
const withDynamo = Boolean(process.env.AWS_ENDPOINT_URL_DYNAMODB);
const selected = mutants.filter((m) => !m.int || withDynamo);

/** True if every listed test passes. */
function passes(m: Pick<Mutant, 'tests' | 'int'>): boolean {
  try {
    if (m.tests?.length) execFileSync('npx', ['jest', '--silent', ...m.tests], { cwd: root, stdio: 'pipe', timeout: 600_000 });
    if (m.int?.length) execFileSync('npx', ['jest', '-c', 'jest.integration.config.js', '--silent', ...m.int], { cwd: root, stdio: 'pipe', timeout: 600_000 });
    return true;
  } catch {
    return false;
  }
}

// A mutant only counts as killed if the same tests pass without it.
const all = { tests: [...new Set(selected.flatMap((m) => m.tests ?? []))], int: [...new Set(selected.flatMap((m) => m.int ?? []))] };
if (!passes(all)) throw new Error('The tests fail without any mutant. Fix that first (and run npm run bundle).');

let survived = 0;
for (const m of selected) {
  const path = join(root, m.file);
  const original = readFileSync(path, 'utf8');
  if (original.split(m.from).length !== 2) throw new Error(`"${m.name}": the text to mutate must appear exactly once in ${m.file}`);
  writeFileSync(path, original.replace(m.from, m.to));
  let killed: boolean;
  try {
    killed = !passes(m);
  } finally {
    writeFileSync(path, original);
  }
  if (!killed) survived++;
  process.stdout.write(`${killed ? 'killed  ' : 'SURVIVED'}  ${m.name}\n`);
}
const skipped = mutants.length - selected.length;
process.stdout.write(`\n${selected.length - survived} of ${selected.length} mutants killed${skipped ? `, ${skipped} skipped (set AWS_ENDPOINT_URL_DYNAMODB)` : ''}\n`);
process.exit(survived === 0 ? 0 : 1);
