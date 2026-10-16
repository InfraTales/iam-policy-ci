import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { CiRoleStack } from '../../infra/lib/ci-role-stack';
import { synthApp } from '../support/synth';

const synth = synthApp();
const exportT = Template.fromStack(synth.exportStack);
const ciT = Template.fromStack(synth.ciStack);

test('cdk-nag AWS Solutions finds nothing unacknowledged', () => {
  expect(synth.nagViolations).toEqual([]);
});

test('no role in the app attaches a managed policy', () => {
  for (const t of [exportT, ciT]) {
    for (const role of Object.values(t.findResources('AWS::IAM::Role'))) {
      expect(role.Properties.ManagedPolicyArns).toBeUndefined();
    }
  }
});

test('the function runs on Node.js 24, arm64, with its own role', () => {
  exportT.hasResourceProperties('AWS::Lambda::Function', {
    Runtime: 'nodejs24.x',
    Architectures: ['arm64'],
    Role: { 'Fn::GetAtt': [Match.stringLikeRegexp('^ExportFunctionRole'), 'Arn'] },
  });
});

test('the bucket blocks public access and refuses plain HTTP', () => {
  exportT.hasResourceProperties('AWS::S3::Bucket', {
    PublicAccessBlockConfiguration: { BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true },
  });
  exportT.hasResourceProperties('AWS::S3::BucketPolicy', {
    PolicyDocument: { Statement: Match.arrayWith([Match.objectLike({ Effect: 'Deny', Condition: { Bool: { 'aws:SecureTransport': 'false' } } })]) },
  });
});

test('only main and pull requests of one repository can assume the CI role', () => {
  ciT.hasResourceProperties('AWS::IAM::Role', {
    MaxSessionDuration: 3600,
    AssumeRolePolicyDocument: {
      Statement: [
        Match.objectLike({
          Action: 'sts:AssumeRoleWithWebIdentity',
          Condition: {
            StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' },
            StringLike: {
              'token.actions.githubusercontent.com:sub': [
                'repo:InfraTales/iam-policy-ci:ref:refs/heads/main',
                'repo:InfraTales/iam-policy-ci:pull_request',
              ],
            },
          },
        }),
      ],
    },
  });
});

test('the CI role can call the four Access Analyzer APIs and nothing else', () => {
  const policies = Object.values(ciT.findResources('AWS::IAM::Policy'));
  expect(policies).toHaveLength(1);
  expect(policies[0]!.Properties.PolicyDocument.Statement).toEqual([
    {
      Sid: 'RunPolicyChecks',
      Effect: 'Allow',
      Action: [
        'access-analyzer:CheckAccessNotGranted',
        'access-analyzer:CheckNoNewAccess',
        'access-analyzer:CheckNoPublicAccess',
        'access-analyzer:ValidatePolicy',
      ],
      Resource: '*',
    },
  ]);
});

test('an existing OIDC provider is reused instead of creating a second one', () => {
  const stack = new CiRoleStack(new App(), 'Reuse', {
    githubRepo: 'octo/repo',
    oidcProviderArn: 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com',
  });
  Template.fromStack(stack).resourceCountIs('AWS::IAM::OIDCProvider', 0);
});

test('a malformed repository name is refused', () => {
  expect(() => new CiRoleStack(new App(), 'Bad', { githubRepo: 'repo:*' })).toThrow(/owner\/name/);
});
