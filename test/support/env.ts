// Tests never talk to real AWS. A Region keeps the SDK from looking one up, and the
// fake keys are AWS's documented examples, so nothing here is a secret.
process.env.AWS_REGION ??= 'us-east-1';
process.env.AWS_ACCESS_KEY_ID ??= 'AKIAIOSFODNN7EXAMPLE';
process.env.AWS_SECRET_ACCESS_KEY ??= 'not-a-secret';
// A call that slips past a mock goes to a closed local port, never to AWS.
// Service-specific variables (AWS_ENDPOINT_URL_DYNAMODB for DynamoDB Local) still win.
process.env.AWS_ENDPOINT_URL ??= 'http://127.0.0.1:1';
