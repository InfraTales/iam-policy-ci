import { Duration, RemovalPolicy, Stack, type StackProps, Validations } from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import type { Construct } from 'constructs';
import { join } from 'node:path';

export interface ExportStackProps extends StackProps {
  /** Folder with the bundled handler (index.js). `npm run bundle` builds it. */
  codePath?: string;
}

/**
 * A small app with real IAM in it: a Lambda function that exports one day of orders
 * from DynamoDB to S3. Every permission is written out by hand, so the policy check
 * sees exactly what the function can do.
 */
export class ExportStack extends Stack {
  readonly role: iam.Role;
  readonly bucket: s3.Bucket;
  readonly table: dynamodb.Table;

  constructor(scope: Construct, id: string, props: ExportStackProps = {}) {
    super(scope, id, props);

    this.table = new dynamodb.Table(this, 'OrdersTable', {
      partitionKey: { name: 'day', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'orderId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    this.bucket = new s3.Bucket(this, 'ExportBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      lifecycleRules: [{ prefix: 'exports/', expiration: Duration.days(30) }],
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const logGroup = new logs.LogGroup(this, 'ExportFunctionLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Our own role instead of the default one. The default attaches the AWS managed
    // AWSLambdaBasicExecutionRole policy, whose contents aren't in the template.
    this.role = new iam.Role(this, 'ExportFunctionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Export function: query orders, write exports, write its own logs',
    });
    this.role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'WriteOwnLogs',
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [logGroup.logGroupArn],
      }),
    );
    // table.grantReadData() would also add Scan, GetItem, BatchGetItem and more.
    // The handler only queries.
    this.role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'QueryOrders',
        actions: ['dynamodb:Query'],
        resources: [this.table.tableArn],
      }),
    );
    // bucket.grantPut() would add s3:Abort* and the tagging, legal hold and retention actions.
    this.role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'WriteExports',
        actions: ['s3:PutObject'],
        resources: [this.bucket.arnForObjects('exports/*')],
      }),
    );

    const fn = new lambda.Function(this, 'ExportFunction', {
      runtime: lambda.Runtime.NODEJS_24_X,
      architecture: lambda.Architecture.ARM_64,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(props.codePath ?? join(__dirname, '..', '..', 'build', 'export')),
      role: this.role,
      logGroup,
      memorySize: 256,
      timeout: Duration.seconds(60),
      environment: {
        TABLE_NAME: this.table.tableName,
        BUCKET_NAME: this.bucket.bucketName,
      },
    });

    void fn;

    // cdk-nag acknowledgements, each scoped to one construct and one finding.
    const bucketId = this.getLogicalId(this.bucket.node.defaultChild as s3.CfnBucket);
    Validations.of(this.role.node.findChild('DefaultPolicy')).acknowledge({
      id: `AwsSolutions::AwsSolutions-IAM5[Resource::<${bucketId}.Arn>/exports/*]`,
      reason: 'The function writes one object per day, exports/<day>.json, so it needs exports/* and nothing wider.',
    });
    Validations.of(this.bucket).acknowledge({
      id: 'AwsSolutions::AwsSolutions-S1',
      reason:
        'Server access logs need a second bucket and add cost. Only one role writes here; turn on ' +
        'CloudTrail data events if you need an audit trail of object access.',
    });
  }
}
