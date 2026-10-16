import { DynamoDBDocumentClient, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { mockClient } from 'aws-sdk-client-mock';
import { extractTemplate, loadAssembly } from '../../policy-check/extract';
import { synthApp } from '../support/synth';

// The other half of least privilege: the role must not grant more than the code calls,
// and the code must not call anything the role doesn't grant. We run the real handler
// with mocked AWS clients, turn each SDK call into the IAM action it needs, and compare
// that list with the synthesized policy.

const ddb = mockClient(DynamoDBDocumentClient);
const s3 = mockClient(S3Client);

const { dir } = synthApp();
const template = loadAssembly(dir).find((s) => s.stackName === 'IamPolicyCi-Export')!.template;
const role = extractTemplate('IamPolicyCi-Export', template).principals[0]!;

const glob = (pattern: string) => new RegExp(`^${pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
const list = (v: unknown) => (Array.isArray(v) ? v : [v]) as string[];

function grants(action: string, resource: string): boolean {
  return role.merged.Statement.some(
    (s) =>
      s.Effect === 'Allow' &&
      list(s.Action).some((a) => glob(a).test(action)) &&
      list(s.Resource).some((r) => glob(r).test(resource)),
  );
}

const tableName = /table\/(.+)$/.exec(list(role.merged.Statement[1]!.Resource)[0]!)![1]!;
const bucketName = /^arn:aws:s3:::([^/]+)\//.exec(list(role.merged.Statement[2]!.Resource)[0]!)![1]!;

test('every AWS call the handler makes is allowed, and every grant is used', async () => {
  process.env.TABLE_NAME = tableName;
  process.env.BUCKET_NAME = bucketName;
  ddb.on(QueryCommand).resolvesOnce({ Items: [], LastEvaluatedKey: { day: 'x' } }).resolves({ Items: [] });
  s3.on(PutObjectCommand).resolves({});
  const { handler } = await import('../../app/src/export-handler');
  await handler({ day: '2026-10-16' });

  const used = [
    ...ddb.calls().map((c) => {
      const cmd = c.args[0] as QueryCommand;
      return { action: `dynamodb:${cmd.constructor.name.replace(/Command$/, '')}`, resource: `arn:aws:dynamodb:us-east-1:123456789012:table/${cmd.input.TableName}` };
    }),
    ...s3.calls().map((c) => {
      const cmd = c.args[0] as PutObjectCommand;
      return { action: `s3:${cmd.constructor.name.replace(/Command$/, '')}`, resource: `arn:aws:s3:::${cmd.input.Bucket}/${cmd.input.Key}` };
    }),
  ];
  expect(used.map((u) => u.action)).toEqual(['dynamodb:Query', 'dynamodb:Query', 's3:PutObject']);
  for (const u of used) expect({ ...u, allowed: grants(u.action, u.resource) }).toEqual({ ...u, allowed: true });

  // Lambda itself writes the logs, so the handler never calls logs:* directly.
  const granted = role.merged.Statement.flatMap((s) => list(s.Action)).filter((a) => !a.startsWith('logs:'));
  expect(granted.sort()).toEqual([...new Set(used.map((u) => u.action))].sort());
});
