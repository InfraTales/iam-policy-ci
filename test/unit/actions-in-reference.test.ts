import { actionsOutsideReference } from '../../policy-check/checks';

const reference = {
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: ['s3:PutObject', 'dynamodb:Query'], Resource: '*' },
    { Effect: 'Allow', Action: 'logs:*', Resource: '*' },
  ],
};
const policy = (...statements: Record<string, unknown>[]) => ({ Version: '2012-10-17', Statement: statements });

test('actions the reference lists pass, matched without regard to case', () => {
  expect(actionsOutsideReference(policy({ Effect: 'Allow', Action: ['S3:putobject', 'dynamodb:Query'], Resource: '*' }), reference)).toEqual([]);
});

test('a reference wildcard covers narrower actions and narrower wildcards', () => {
  expect(actionsOutsideReference(policy({ Effect: 'Allow', Action: ['logs:PutLogEvents', 'logs:Create*'], Resource: '*' }), reference)).toEqual([]);
});

test('a wider wildcard than the reference fails', () => {
  expect(actionsOutsideReference(policy({ Sid: 'Wide', Effect: 'Allow', Action: 's3:*', Resource: '*' }), reference)).toEqual([
    'statement "Wide" grants s3:*',
  ]);
});

test('an action the reference leaves out fails; Deny statements are ignored', () => {
  expect(
    actionsOutsideReference(
      policy({ Effect: 'Allow', Action: 's3:DeleteObject', Resource: '*' }, { Effect: 'Deny', Action: 'iam:*', Resource: '*' }),
      reference,
    ),
  ).toEqual(['statement 0 grants s3:DeleteObject']);
});

test('NotAction in an Allow fails, because it can only be judged by Access Analyzer', () => {
  expect(actionsOutsideReference(policy({ Sid: 'Not', Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }), reference)).toEqual([
    'statement "Not" uses NotAction, which can\'t be compared offline',
  ]);
});
