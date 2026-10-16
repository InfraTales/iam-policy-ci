# Contributing

Thanks for helping. This repo shows how to test IAM policies in CI, so every change has to keep those tests honest.

## Setup

You need Node.js 24 and npm. Docker is only needed for the DynamoDB Local test.

```bash
npm ci
npm run check
docker run -d --rm -p 8024:8000 amazon/dynamodb-local:3.3.2
AWS_ENDPOINT_URL_DYNAMODB=http://localhost:8024 npm run test:int
```

## What a change needs

- Add a test that fails without your change. For a bug, write the failing test first, then break the fix on purpose once and check that the test notices.
- Write permissions out by hand. CDK's `grant*` helpers add actions the handler doesn't call, and `test/policy/actions-used.test.ts` fails if a role grants an action the code doesn't use.
- Update the reference policy in `policy-check/reference/` in the same pull request when a role gains access.
- Give every cdk-nag acknowledgement a written reason, scoped to one construct and one finding.
- Keep tests away from real AWS. `test/support/env.ts` points every SDK client at a closed local port, so a missing mock fails fast.

## Pull requests

Branch from `main`, keep each pull request to one change, and explain why in the description. CI must pass before merge.

Found a security problem? Don't open a public issue. [SECURITY.md](SECURITY.md) says where to send it.

---

Created by Rahul Ladumor / InfraTales
