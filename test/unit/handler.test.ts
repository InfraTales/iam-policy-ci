import { DynamoDBDocumentClient, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { mockClient } from 'aws-sdk-client-mock';
import { handler } from '../../app/src/export-handler';

const ddb = mockClient(DynamoDBDocumentClient);
const s3 = mockClient(S3Client);

beforeEach(() => {
  ddb.reset();
  s3.reset();
  process.env.TABLE_NAME = 'orders';
  process.env.BUCKET_NAME = 'exports-bucket';
});

test('rejects a day that is not YYYY-MM-DD before calling AWS', async () => {
  await expect(handler({ day: '../../etc' })).rejects.toThrow(/event.day/);
  await expect(handler({} as { day: string })).rejects.toThrow(/event.day/);
  expect(ddb.calls()).toHaveLength(0);
});

test('fails loudly when its configuration is missing', async () => {
  delete process.env.BUCKET_NAME;
  await expect(handler({ day: '2026-10-16' })).rejects.toThrow('Missing required environment variable BUCKET_NAME');
});

test('writes exports/<day>.json with every order for that day', async () => {
  ddb.on(QueryCommand).resolves({ Items: [{ day: '2026-10-16', orderId: 'o1' }] });
  s3.on(PutObjectCommand).resolves({});
  await expect(handler({ day: '2026-10-16' })).resolves.toEqual({ key: 'exports/2026-10-16.json', count: 1 });
  const put = s3.commandCalls(PutObjectCommand)[0]!.args[0].input;
  expect(put.Bucket).toBe('exports-bucket');
  expect(JSON.parse(put.Body as string)).toEqual({ day: '2026-10-16', count: 1, orders: [{ day: '2026-10-16', orderId: 'o1' }] });
});
