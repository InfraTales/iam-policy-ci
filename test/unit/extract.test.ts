import { extractTemplate, loadAssembly } from '../../policy-check/extract';
import type { CfnTemplate } from '../../policy-check/resolve';
import { synthApp } from '../support/synth';

const roleTrust = {
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }],
};

describe('the synthesized app', () => {
  const { dir } = synthApp();
  const stacks = loadAssembly(dir);
  const exportStack = stacks.find((s) => s.stackName === 'IamPolicyCi-Export');
  const result = extractTemplate('IamPolicyCi-Export', exportStack!.template);

  test('finds both stacks in the cloud assembly', () => {
    expect(stacks.map((s) => s.stackName).sort()).toEqual(['IamPolicyCi-CiRole', 'IamPolicyCi-Export']);
  });

  test('groups the function role with its policy and resolves every token', () => {
    expect(result.principals).toHaveLength(1);
    const role = result.principals[0]!;
    expect(role.logicalId).toMatch(/^ExportFunctionRole/);
    expect(role.externalManagedPolicyArns).toEqual([]);
    const text = JSON.stringify(role.merged);
    expect(text).not.toContain('Fn::');
    expect(text).not.toContain('"Ref"');
    expect(role.merged.Statement.map((s) => s.Action)).toEqual([
      ['logs:CreateLogStream', 'logs:PutLogEvents'],
      'dynamodb:Query',
      's3:PutObject',
    ]);
    expect(role.merged.Statement[2]!.Resource).toMatch(/^arn:aws:s3:::exportbucket[0-9a-f]+\/exports\/\*$/);
  });

  test('finds the bucket policy and the trust policy', () => {
    expect(result.resourcePolicies.map((r) => r.resourceType).sort()).toEqual([
      'AWS::IAM::AssumeRolePolicyDocument',
      'AWS::S3::Bucket',
    ]);
  });
});

describe('templates written by hand', () => {
  test('inline policies, attached managed policies and AWS managed policies all count', () => {
    const template: CfnTemplate = {
      Resources: {
        R: {
          Type: 'AWS::IAM::Role',
          Properties: {
            AssumeRolePolicyDocument: roleTrust,
            Policies: [{ PolicyName: 'inline', PolicyDocument: { Statement: [{ Effect: 'Allow', Action: 'sqs:SendMessage', Resource: '*' }] } }],
            ManagedPolicyArns: [{ Ref: 'MP' }, 'arn:aws:iam::aws:policy/ReadOnlyAccess'],
          },
        },
        MP: {
          Type: 'AWS::IAM::ManagedPolicy',
          Properties: { PolicyDocument: { Statement: { Effect: 'Allow', Action: 'sns:Publish', Resource: '*' } } },
        },
      },
    };
    const [p] = extractTemplate('S', template).principals;
    expect(p!.merged.Statement.map((s) => s.Action).sort()).toEqual(['sns:Publish', 'sqs:SendMessage']);
    expect(p!.externalManagedPolicyArns).toEqual(['arn:aws:iam::aws:policy/ReadOnlyAccess']);
  });

  test('a policy attached to a role outside the template fails, because its total access is unknown', () => {
    const template: CfnTemplate = {
      Resources: {
        P: {
          Type: 'AWS::IAM::Policy',
          Properties: { PolicyDocument: { Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }] }, Roles: ['imported-role'] },
        },
      },
    };
    expect(() => extractTemplate('S', template)).toThrow(/isn't a Ref/);
  });

  test('a policy whose Roles entry points at something other than a role, user or group fails', () => {
    const template: CfnTemplate = {
      Resources: {
        Bucket: { Type: 'AWS::S3::Bucket', Properties: {} },
        P: {
          Type: 'AWS::IAM::Policy',
          Properties: { PolicyDocument: { Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }] }, Roles: [{ Ref: 'Bucket' }] },
        },
      },
    };
    expect(() => extractTemplate('S', template)).toThrow(/attaches to Bucket, which isn't a role, user or group in S/);
  });

  test('queue, topic, key and secret policies are found; Lambda permissions are listed as not checked', () => {
    const doc = { Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:root' }, Action: '*', Resource: '*' }] };
    const template: CfnTemplate = {
      Resources: {
        Q: { Type: 'AWS::SQS::Queue' },
        QP: { Type: 'AWS::SQS::QueuePolicy', Properties: { Queues: [{ Ref: 'Q' }], PolicyDocument: doc } },
        K: { Type: 'AWS::KMS::Key', Properties: { KeyPolicy: doc } },
        SP: { Type: 'AWS::SecretsManager::ResourcePolicy', Properties: { SecretId: { Ref: 'Sec' }, ResourcePolicy: doc } },
        Sec: { Type: 'AWS::SecretsManager::Secret' },
        LP: { Type: 'AWS::Lambda::Permission', Properties: {} },
      },
    };
    const r = extractTemplate('S', template);
    expect(r.resourcePolicies.map((p) => `${p.resourceType}:${p.logicalId}`).sort()).toEqual([
      'AWS::KMS::Key:K',
      'AWS::SQS::Queue:Q',
      'AWS::SecretsManager::Secret:Sec',
    ]);
    expect(r.unchecked).toEqual([{ stack: 'S', logicalId: 'LP', type: 'AWS::Lambda::Permission' }]);
  });

  test('an empty policy fails instead of passing every check', () => {
    const template: CfnTemplate = {
      Resources: { B: { Type: 'AWS::S3::Bucket' }, BP: { Type: 'AWS::S3::BucketPolicy', Properties: { Bucket: { Ref: 'B' }, PolicyDocument: { Statement: [] } } } },
    };
    expect(() => extractTemplate('S', template)).toThrow(/no statements/);
  });
});
