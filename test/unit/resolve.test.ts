import { type CfnTemplate, placeholderName, resolve, type ResolveContext, UnresolvableError } from '../../policy-check/resolve';

const template: CfnTemplate = {
  Parameters: { Env: { Default: 'dev' }, NoDefault: {} },
  Resources: {
    Bucket1: { Type: 'AWS::S3::Bucket' },
    Named: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'my-named-bucket' } },
    Table1: { Type: 'AWS::DynamoDB::Table' },
    Global1: { Type: 'AWS::DynamoDB::GlobalTable' },
    Role1: { Type: 'AWS::IAM::Role' },
    Logs1: { Type: 'AWS::Logs::LogGroup', Properties: { LogGroupName: '/app/logs' } },
    Queue1: { Type: 'AWS::SQS::Queue' },
    Oidc1: { Type: 'AWS::IAM::OIDCProvider', Properties: { Url: 'https://token.actions.githubusercontent.com' } },
    Weird1: { Type: 'AWS::Custom::Thing' },
  },
};
const ctx: ResolveContext = { template, stackName: 'S', partition: 'aws', region: 'us-east-1', account: '123456789012' };

test('pseudo parameters become the placeholder account and Region', () => {
  expect(resolve({ 'Fn::Sub': 'arn:${AWS::Partition}:sqs:${AWS::Region}:${AWS::AccountId}:q' }, ctx)).toBe(
    'arn:aws:sqs:us-east-1:123456789012:q',
  );
});

test('GetAtt Arn builds an ARN with the right shape for each type', () => {
  expect(resolve({ 'Fn::GetAtt': ['Bucket1', 'Arn'] }, ctx)).toBe('arn:aws:s3:::bucket1');
  expect(resolve({ 'Fn::GetAtt': ['Table1', 'Arn'] }, ctx)).toBe('arn:aws:dynamodb:us-east-1:123456789012:table/Table1');
  expect(resolve({ 'Fn::GetAtt': ['Global1', 'Arn'] }, ctx)).toBe('arn:aws:dynamodb:us-east-1:123456789012:table/Global1');
  expect(resolve({ 'Fn::GetAtt': ['Role1', 'Arn'] }, ctx)).toBe('arn:aws:iam::123456789012:role/Role1');
  expect(resolve({ 'Fn::GetAtt': 'Logs1.Arn' }, ctx)).toBe('arn:aws:logs:us-east-1:123456789012:log-group:/app/logs:*');
  expect(resolve({ Ref: 'Oidc1' }, ctx)).toBe('arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com');
});

test('an explicit physical name wins over the logical ID', () => {
  expect(placeholderName('Named', ctx)).toBe('my-named-bucket');
  expect(resolve({ Ref: 'Named' }, ctx)).toBe('my-named-bucket');
});

test('Join, Sub with variables, Select and Split resolve like CloudFormation', () => {
  expect(resolve({ 'Fn::Join': ['', [{ 'Fn::GetAtt': ['Bucket1', 'Arn'] }, '/exports/*']] }, ctx)).toBe('arn:aws:s3:::bucket1/exports/*');
  expect(resolve({ 'Fn::Sub': ['${B}/x/${!Literal}', { B: { Ref: 'Bucket1' } }] }, ctx)).toBe('bucket1/x/${Literal}');
  expect(resolve({ 'Fn::Sub': '${Table1.Arn}/index/*' }, ctx)).toBe('arn:aws:dynamodb:us-east-1:123456789012:table/Table1/index/*');
  expect(resolve({ 'Fn::Select': [1, { 'Fn::Split': ['/', 'a/b/c'] }] }, ctx)).toBe('b');
  expect(resolve({ Ref: 'Env' }, ctx)).toBe('dev');
  expect(resolve({ Ref: 'Queue1' }, ctx)).toBe('https://sqs.us-east-1.amazonaws.com/123456789012/Queue1');
});

test('AWS::NoValue removes the key or list item', () => {
  expect(resolve({ A: 'x', B: { Ref: 'AWS::NoValue' }, C: ['y', { Ref: 'AWS::NoValue' }] }, ctx)).toEqual({ A: 'x', C: ['y'] });
});

test('anything it cannot resolve fails instead of passing through', () => {
  expect(() => resolve({ 'Fn::If': ['Cond', 'a', 'b'] }, ctx)).toThrow(UnresolvableError);
  expect(() => resolve({ 'Fn::ImportValue': 'Other-Export' }, ctx)).toThrow(UnresolvableError);
  expect(() => resolve({ Ref: 'Missing' }, ctx)).toThrow(/Unknown logical ID Missing/);
  expect(() => resolve({ Ref: 'NoDefault' }, ctx)).toThrow(/no default/);
  expect(() => resolve({ 'Fn::GetAtt': ['Weird1', 'Arn'] }, ctx)).toThrow(/No placeholder ARN/);
  expect(() => resolve({ 'Fn::GetAtt': ['Bucket1', 'DomainName'] }, ctx)).toThrow(/not supported/);
  expect(() => resolve({ 'Fn::Select': [5, ['a']] }, ctx)).toThrow(/out of range/);
});
