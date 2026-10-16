import {
  AccessAnalyzerClient,
  CheckAccessNotGrantedCommand,
  CheckNoNewAccessCommand,
  CheckNoPublicAccessCommand,
  ValidatePolicyCommand,
} from '@aws-sdk/client-accessanalyzer';
import * as iam from 'aws-cdk-lib/aws-iam';
import { mockClient } from 'aws-sdk-client-mock';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { main } from '../../policy-check/cli';
import { config as realConfig, type PolicyCheckConfig } from '../../policy-check/config';
import { synthApp } from '../support/synth';

// No local engine exists for IAM Access Analyzer, so these tests mock the API.
// They prove what we send and how we react to each answer. The verdicts themselves
// come from AWS when CI runs `npm run policy-check` with credentials.

const aa = mockClient(AccessAnalyzerClient);
const client = new AccessAnalyzerClient({ region: 'us-east-1' });
const PASS = { result: 'PASS' as const, message: 'ok', reasons: [] };

function passEverything() {
  aa.reset();
  aa.on(ValidatePolicyCommand).resolves({ findings: [] });
  aa.on(CheckNoNewAccessCommand).resolves(PASS);
  aa.on(CheckAccessNotGrantedCommand).resolves(PASS);
  aa.on(CheckNoPublicAccessCommand).resolves(PASS);
}

async function run(dir: string, extra: string[] = [], config: PolicyCheckConfig = realConfig) {
  const lines: string[] = [];
  const code = await main(['--assembly', dir, ...extra], { client, config, log: (l) => lines.push(l) });
  return { code, out: lines.join('\n') };
}

const baseline = synthApp();

beforeEach(passEverything);

test('the app as written passes, and every policy reaches the right check', async () => {
  const { code, out } = await run(baseline.dir);
  expect(code).toBe(0);
  expect(aa.commandCalls(ValidatePolicyCommand)).toHaveLength(5);
  expect(aa.commandCalls(CheckNoNewAccessCommand)).toHaveLength(2);
  expect(aa.commandCalls(CheckAccessNotGrantedCommand)).toHaveLength(2);
  expect(aa.commandCalls(CheckNoPublicAccessCommand)).toHaveLength(3);
  expect(out).toContain('7 billed custom checks');
});

test('CheckNoNewAccess compares the resolved role policy with its reference file', async () => {
  await run(baseline.dir);
  const call = aa
    .commandCalls(CheckNoNewAccessCommand)
    .map((c) => c.args[0].input)
    .find((i) => i.newPolicyDocument?.includes('dynamodb:Query'));
  expect(call?.policyType).toBe('IDENTITY_POLICY');
  expect(JSON.parse(call!.existingPolicyDocument!)).toEqual(
    JSON.parse(readFileSync(join(__dirname, '../../policy-check/reference/export-function.json'), 'utf8')),
  );
  expect(call!.newPolicyDocument).not.toContain('Fn::');
});

test('ValidatePolicy gets the resource type for bucket and trust policies', async () => {
  await run(baseline.dir);
  const types = aa
    .commandCalls(ValidatePolicyCommand)
    .map((c) => `${c.args[0].input.policyType}:${c.args[0].input.validatePolicyResourceType ?? '-'}`)
    .sort();
  expect(types).toEqual([
    'IDENTITY_POLICY:-',
    'IDENTITY_POLICY:-',
    'RESOURCE_POLICY:AWS::IAM::AssumeRolePolicyDocument',
    'RESOURCE_POLICY:AWS::IAM::AssumeRolePolicyDocument',
    'RESOURCE_POLICY:AWS::S3::Bucket',
  ]);
});

describe('adding s3:* to the function role', () => {
  const broken = synthApp(({ exportStack }) =>
    exportStack.role.addToPolicy(
      new iam.PolicyStatement({ sid: 'Oops', actions: ['s3:*'], resources: [exportStack.bucket.arnForObjects('*')] }),
    ),
  );

  test('sends the new statement to CheckNoNewAccess and fails the build when AWS says FAIL', async () => {
    aa.on(CheckNoNewAccessCommand).callsFake((input: { newPolicyDocument: string }) =>
      input.newPolicyDocument.includes('"s3:*"')
        ? { result: 'FAIL', message: 'test answer: new access', reasons: [{ statementId: 'Oops', description: 'test answer' }] }
        : PASS,
    );
    const { code, out } = await run(broken.dir);
    expect(code).toBe(1);
    expect(out).toMatch(/FAIL CheckNoNewAccess IamPolicyCi-Export\/ExportFunctionRole/);
    expect(out).toContain('statement "Oops"');
  });

  test('a dry run fails it offline, with no AWS call, because the reference has no s3:*', async () => {
    const { code, out } = await run(broken.dir, ['--dry-run']);
    expect(code).toBe(1);
    expect(aa.calls()).toHaveLength(0);
    expect(out).toMatch(/FAIL ActionsInReference IamPolicyCi-Export\/ExportFunctionRole/);
    expect(out).toContain('statement "Oops" grants s3:*, which export-function.json doesn\'t allow');
  });

  test('cdk-nag catches it too, as AwsSolutions-IAM5', () => {
    expect(broken.nagViolations.join('\n')).toContain('AwsSolutions-IAM5[Action::s3:*]');
  });
});

describe('adding s3:DeleteObject on exports/*, with no new wildcard', () => {
  const broken = synthApp(({ exportStack }) =>
    exportStack.role.addToPolicy(
      new iam.PolicyStatement({ sid: 'Cleanup', actions: ['s3:DeleteObject'], resources: [exportStack.bucket.arnForObjects('exports/*')] }),
    ),
  );

  test('cdk-nag says nothing, because the wildcard on exports/* is already acknowledged', () => {
    expect(broken.nagViolations).toEqual([]);
  });

  test('the offline action check fails it too, even though cdk-nag passes', async () => {
    const { code, out } = await run(broken.dir, ['--dry-run']);
    expect(code).toBe(1);
    expect(out).toContain('statement "Cleanup" grants s3:DeleteObject');
  });

  test('the new action still reaches CheckNoNewAccess', async () => {
    await run(broken.dir);
    const sent = aa.commandCalls(CheckNoNewAccessCommand).map((c) => c.args[0].input.newPolicyDocument ?? '');
    expect(sent.some((d) => d.includes('s3:DeleteObject'))).toBe(true);
  });
});

describe('making the bucket public', () => {
  const broken = synthApp(({ exportStack }) =>
    exportStack.bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'PublicRead',
        actions: ['s3:GetObject'],
        principals: [new iam.AnyPrincipal()],
        resources: [exportStack.bucket.arnForObjects('*')],
      }),
    ),
  );

  test('sends the bucket policy to CheckNoPublicAccess as an S3 bucket and fails on FAIL', async () => {
    aa.on(CheckNoPublicAccessCommand).callsFake((input: { policyDocument: string; resourceType: string }) =>
      input.resourceType === 'AWS::S3::Bucket' && input.policyDocument.includes('PublicRead')
        ? { result: 'FAIL', message: 'test answer: public', reasons: [{ statementId: 'PublicRead', description: 'test answer' }] }
        : PASS,
    );
    const { code, out } = await run(broken.dir);
    expect(code).toBe(1);
    expect(out).toMatch(/FAIL CheckNoPublicAccess IamPolicyCi-Export\/ExportBucketPolicy\w+ \(AWS::S3::Bucket\)/);
  });

  test('cdk-nag has no rule for a public principal in a bucket policy', () => {
    expect(broken.nagViolations).toEqual([]);
  });
});

test('a ValidatePolicy SECURITY_WARNING fails; a WARNING or SUGGESTION is printed only', async () => {
  aa.on(ValidatePolicyCommand).resolves({
    findings: [
      { findingType: 'SUGGESTION', issueCode: 'EMPTY_ARRAY_ACTION', findingDetails: 'x', learnMoreLink: '', locations: [] },
      { findingType: 'WARNING', issueCode: 'MISSING_VERSION', findingDetails: 'y', learnMoreLink: '', locations: [] },
    ],
  });
  expect((await run(baseline.dir)).code).toBe(0);

  aa.on(ValidatePolicyCommand).resolves({
    findings: [{ findingType: 'SECURITY_WARNING', issueCode: 'PASS_ROLE_WITH_STAR_IN_RESOURCE', findingDetails: 'z', learnMoreLink: '', locations: [] }],
  });
  const { code, out } = await run(baseline.dir);
  expect(code).toBe(1);
  expect(out).toContain('SECURITY_WARNING PASS_ROLE_WITH_STAR_IN_RESOURCE');
});

test('an ignored finding needs a matching issue code and origin', async () => {
  aa.on(ValidatePolicyCommand).resolves({
    findings: [{ findingType: 'SECURITY_WARNING', issueCode: 'PASS_ROLE_WITH_STAR_IN_RESOURCE', findingDetails: 'z', learnMoreLink: '', locations: [] }],
  });
  const config: PolicyCheckConfig = {
    ...realConfig,
    ignoredFindings: [{ issueCode: 'PASS_ROLE_WITH_STAR_IN_RESOURCE', origin: /./, reason: 'test' }],
  };
  expect((await run(baseline.dir, [], config)).code).toBe(0);
  const narrow = { ...config, ignoredFindings: [{ ...config.ignoredFindings[0]!, origin: /NoSuchRole/ }] };
  expect((await run(baseline.dir, [], narrow)).code).toBe(1);
});

test('ValidatePolicy follows nextToken until the last page', async () => {
  aa.on(ValidatePolicyCommand)
    .resolvesOnce({ findings: [], nextToken: 'page2' })
    .resolves({
      findings: [{ findingType: 'ERROR', issueCode: 'INVALID_ACTION', findingDetails: 'bad', learnMoreLink: '', locations: [] }],
    });
  const { code } = await run(baseline.dir);
  expect(code).toBe(1);
  // Checks run four at a time, so look for the follow-up call anywhere in the list.
  const tokens = aa.commandCalls(ValidatePolicyCommand).map((c) => c.args[0].input.nextToken);
  expect(tokens.filter((t) => t === 'page2')).toHaveLength(1);
  expect(tokens).toHaveLength(6); // 5 policies, one of them with a second page
});

test('an answer with no result counts as a failure', async () => {
  aa.on(CheckNoPublicAccessCommand).resolves({});
  expect((await run(baseline.dir)).code).toBe(1);
});

test('an API error stops the run with exit code 2', async () => {
  aa.on(CheckNoNewAccessCommand).rejects(new Error('AccessDeniedException'));
  const { code, out } = await run(baseline.dir);
  expect(code).toBe(2);
  expect(out).toContain('AccessDeniedException');
});

test('a principal with no reference policy fails, even in a dry run', async () => {
  const config: PolicyCheckConfig = { ...realConfig, references: realConfig.references.slice(0, 1) };
  const { code, out } = await run(baseline.dir, ['--dry-run'], config);
  expect(code).toBe(1);
  expect(out).toMatch(/FAIL ReferenceExists IamPolicyCi-CiRole\/PolicyCheckRole/);
  expect(aa.calls()).toHaveLength(0);
});

test('an AWS managed policy fails unless it is on the allow list', async () => {
  const withManaged = synthApp(({ exportStack }) =>
    exportStack.role.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess')),
  );
  const { code, out } = await run(withManaged.dir, ['--dry-run']);
  expect(code).toBe(1);
  expect(out).toContain("attaches arn:aws:iam::aws:policy/ReadOnlyAccess, which isn't in allowedManagedPolicyArns");
});

test('more than 100 never-grant actions are split across calls', async () => {
  const neverGrant = Array.from({ length: 150 }, (_, i) => `s3:Fake${i}`);
  await run(baseline.dir, [], { ...realConfig, neverGrant });
  const sizes = aa.commandCalls(CheckAccessNotGrantedCommand).map((c) => c.args[0].input.access?.[0]?.actions?.length);
  expect(sizes).toEqual([100, 50, 100, 50]);
});

test('a dry run makes no AWS calls', async () => {
  const { code, out } = await run(baseline.dir, ['--dry-run']);
  expect(code).toBe(0);
  expect(aa.calls()).toHaveLength(0);
  expect(out).toContain('12 API calls planned, 7 of them billed custom checks');
  expect(out).toMatch(/PASS ActionsInReference IamPolicyCi-Export\/ExportFunctionRole/);
  expect(out).toMatch(/PASS ActionsInReference IamPolicyCi-CiRole\/PolicyCheckRole/);
});

test('a missing cloud assembly is a tool error', async () => {
  const { code, out } = await run('/no/such/dir');
  expect(code).toBe(2);
  expect(out).toContain('Run "npx cdk synth" first');
});
