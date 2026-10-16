# Runbook

## Turn on the real policy check in CI

1. Bootstrap CDK in the account and Region if you haven't: `npx cdk bootstrap`.
2. Deploy the CI role stack. If the account already has a GitHub OIDC provider, pass its ARN, because an account can have only one provider per URL:

   ```bash
   npx cdk deploy IamPolicyCi-CiRole -c githubRepo=<owner>/<name>
   npx cdk deploy IamPolicyCi-CiRole -c githubRepo=<owner>/<name> -c oidcProviderArn=<arn>
   ```

3. Copy the role ARN from the stack, then set it as a repository variable (not a secret, since an ARN isn't secret):

   ```bash
   gh variable set POLICY_CHECK_ROLE_ARN --body arn:aws:iam::<account>:role/<name>
   gh variable set POLICY_CHECK_REGION --body us-east-1   # optional
   ```

4. Push a commit. The `access-analyzer` job now sends every policy to Access Analyzer.

## When the policy check fails

| Output | What it means | What to do |
|---|---|---|
| `FAIL CheckNoNewAccess <role>` | The role can do something its reference policy doesn't allow | Remove the access, or widen the reference file in the same pull request and explain why |
| `FAIL CheckAccessNotGranted <role>` | The role can call an action on the never-grant list | Remove it. If you're sure, change `neverGrant` in `policy-check/config.ts` with a reason |
| `FAIL CheckNoPublicAccess <policy>` | A resource or trust policy grants public access | Add a condition or a specific principal |
| `FAIL ValidatePolicy` with `SECURITY_WARNING` or `ERROR` | A grammar problem or an over-broad grant | Fix the policy. To accept a finding, add it to `ignoredFindings` with a reason |
| `FAIL ReferenceExists <role>` | A new role has no reference policy | Add a reference file and map it in `policy-check/config.ts` |
| `ERROR ...` and exit code 2 | The tool couldn't run: no credentials, throttling, or a template it can't read | Read the message. The run never passes on an error |

## Deploy and remove the demo app

```bash
npm run deploy     # both stacks
npm run destroy
```

CloudFormation keeps the export bucket when you destroy the stack. Empty it and delete it in the S3 console when you're done.
