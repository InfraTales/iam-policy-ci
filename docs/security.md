# Security notes

## The export function's role

The role has three statements and nothing else:

| Statement | Actions | Resource |
|---|---|---|
| WriteOwnLogs | `logs:CreateLogStream`, `logs:PutLogEvents` | The function's own log group |
| QueryOrders | `dynamodb:Query` | The orders table |
| WriteExports | `s3:PutObject` | `exports/*` in the export bucket |

We wrote these by hand instead of using CDK's `grant*` helpers. `table.grantReadData()` also grants `Scan`, `GetItem`, `BatchGetItem` and more. `bucket.grantPut()` also grants `s3:Abort*` and the tagging, legal hold and retention actions. The handler calls none of them.

We also skipped the default Lambda role. It attaches the AWS managed `AWSLambdaBasicExecutionRole` policy, and its contents aren't in the template, so no check here could see them.

## The bucket

Block Public Access is on for all four settings. A bucket policy statement denies any request without TLS. Even if someone adds a public statement, S3 refuses it at deploy time, and CI refuses it first with `CheckNoPublicAccess`.

## The CI role

GitHub Actions assumes `PolicyCheckRole` with OpenID Connect (OIDC), so no long-lived AWS keys sit in GitHub. The trust policy checks two claims:

- `aud` must be `sts.amazonaws.com`.
- `sub` must be `repo:<owner>/<name>:ref:refs/heads/main` or `repo:<owner>/<name>:pull_request`.

IAM refuses to create or update a GitHub trust policy unless it has a `sub` condition whose value isn't only a wildcard. A loose value such as `repo:<org>/*` still passes that check, so the role names one repository's `main` branch and its pull requests. The role's only permission is the four Access Analyzer actions. Those actions have no resource types, so `"Resource": "*"` is the only value IAM accepts for them. Sessions last at most one hour.

## What the policy check doesn't cover

- `AWS::Lambda::Permission`, ECR repository policies, EventBridge bus policies and a few other types. The output lists them as "not checked".
- Service control policies and permission boundaries. The check sees one template at a time.
- Real resource names. Placeholders stand in for them; see the README.
