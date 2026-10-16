import { CreateTableCommand, DeleteTableCommand, DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { BatchWriteCommand, DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import { handler } from '../../app/src/export-handler';

// The real handler against DynamoDB Local. S3 has no local engine here, so it's mocked.
// Run with AWS_ENDPOINT_URL_DYNAMODB=http://localhost:<port> npm run test:int

if (!process.env.AWS_ENDPOINT_URL_DYNAMODB) {
  throw new Error('Set AWS_ENDPOINT_URL_DYNAMODB to a DynamoDB Local endpoint');
}

const raw = new DynamoDBClient({});
const doc = DynamoDBDocumentClient.from(raw);
const s3 = mockClient(S3Client);
const tableName = `orders-${Date.now()}`;

beforeAll(async () => {
  await raw.send(
    new CreateTableCommand({
      TableName: tableName,
      BillingMode: 'PAY_PER_REQUEST',
      AttributeDefinitions: [
        { AttributeName: 'day', AttributeType: 'S' },
        { AttributeName: 'orderId', AttributeType: 'S' },
      ],
      KeySchema: [
        { AttributeName: 'day', KeyType: 'HASH' },
        { AttributeName: 'orderId', KeyType: 'RANGE' },
      ],
    }),
  );
  // 1,200 orders of about 1 KB each: more than the 1 MB a single Query returns,
  // so the handler has to follow LastEvaluatedKey.
  const padding = 'x'.repeat(1000);
  const items = Array.from({ length: 1200 }, (_, i) => ({ day: '2026-10-16', orderId: `o${String(i).padStart(5, '0')}`, padding }));
  items.push({ day: '2026-10-15', orderId: 'other-day', padding });
  for (let i = 0; i < items.length; i += 25) {
    await doc.send(new BatchWriteCommand({ RequestItems: { [tableName]: items.slice(i, i + 25).map((Item) => ({ PutRequest: { Item } })) } }));
  }
  process.env.TABLE_NAME = tableName;
  process.env.BUCKET_NAME = 'exports-bucket';
});

afterAll(async () => {
  await raw.send(new DeleteTableCommand({ TableName: tableName }));
});

test('exports every order for the day across Query pages, and only that day', async () => {
  s3.on(PutObjectCommand).resolves({});
  await expect(handler({ day: '2026-10-16' })).resolves.toEqual({ key: 'exports/2026-10-16.json', count: 1200 });
  const body = JSON.parse(s3.commandCalls(PutObjectCommand)[0]!.args[0].input.Body as string) as { orders: { orderId: string }[] };
  expect(new Set(body.orders.map((o) => o.orderId)).size).toBe(1200);
  expect(body.orders.some((o) => o.orderId === 'other-day')).toBe(false);
});
