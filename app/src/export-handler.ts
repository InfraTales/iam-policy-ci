import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { DynamoDBDocumentClient, QueryCommand, type QueryCommandOutput } from '@aws-sdk/lib-dynamodb';
import { requireEnv } from './env';

/**
 * Exports one day of orders from DynamoDB to a JSON file in S3.
 *
 * The function needs exactly two permissions: dynamodb:Query on the orders table and
 * s3:PutObject under exports/ in the bucket. The stack grants those and nothing else,
 * and test/policy/actions-used.test.ts checks the two lists stay in step.
 */

export interface ExportEvent {
  day: string; // YYYY-MM-DD
}

export interface ExportResult {
  key: string;
  count: number;
}

const DAY = /^\d{4}-\d{2}-\d{2}$/;

// Clients live at module level so warm invocations reuse their connections.
// Endpoints come from the standard AWS_ENDPOINT_URL_<SERVICE> variables in tests.
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3 = new S3Client({});

export async function handler(event: ExportEvent): Promise<ExportResult> {
  if (typeof event?.day !== 'string' || !DAY.test(event.day)) {
    throw new Error('event.day must be a date like 2026-10-16');
  }
  const tableName = requireEnv('TABLE_NAME');
  const bucketName = requireEnv('BUCKET_NAME');

  const orders: Record<string, unknown>[] = [];
  let startKey: QueryCommandOutput['LastEvaluatedKey'];
  do {
    const page = await ddb.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: '#day = :day',
        ExpressionAttributeNames: { '#day': 'day' },
        ExpressionAttributeValues: { ':day': event.day },
        ExclusiveStartKey: startKey,
      }),
    );
    orders.push(...(page.Items ?? []));
    startKey = page.LastEvaluatedKey;
  } while (startKey !== undefined);

  const key = `exports/${event.day}.json`;
  await s3.send(
    new PutObjectCommand({
      Bucket: bucketName,
      Key: key,
      Body: JSON.stringify({ day: event.day, count: orders.length, orders }),
      ContentType: 'application/json',
    }),
  );
  return { key, count: orders.length };
}
