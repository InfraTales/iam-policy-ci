# Cost

Prices are for us-east-1, from the AWS Price List API offer file for `AWSIAMAccessAnalyzer` (version 20260911124556) and the IAM Access Analyzer pricing page, checked on 2026-10-16.

## The policy check

| API | Price | Calls per run in this repo |
|---|---|---|
| `ValidatePolicy` | No additional charge | 5 |
| `CheckNoNewAccess` | $0.002 per call | 2 |
| `CheckAccessNotGranted` | $0.002 per call | 2 |
| `CheckNoPublicAccess` | $0.002 per call | 3 |

That's 7 billed calls, or $0.014 per run. At 20 pull requests a month with 3 pushes each, plus pushes to `main`, you'd run it about 80 times: $1.12. The `--dry-run` output prints the number of billed calls before you spend anything.

The count grows with the app: two custom checks per role (plus one for every 100 actions past the first 100 on the never-grant list) and one per bucket, queue, topic, key, secret or trust policy.

## The app

The app is there to give the check something real to test. If you deploy it, you pay for the Lambda function, DynamoDB on-demand requests, S3 storage and CloudWatch Logs at their normal rates. The table is on-demand, which isn't part of DynamoDB's always-free tier. Exports expire after 30 days, which caps what the bucket holds.

## Related, not used here

The unused access analyzer reports roles, keys and permissions that went unused for a period you choose. It costs $0.20 per IAM role or user per month. It's a good next step after this repo, because it tells you what to remove from a reference policy.
