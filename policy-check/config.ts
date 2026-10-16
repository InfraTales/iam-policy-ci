/**
 * What the policy check enforces. Change this file in a pull request, so a reviewer
 * sees every widening of access next to the reason for it.
 */

export interface ReferenceRule {
  /** Matches `<stack name>/<logical ID>` of a role, user or group. */
  principal: RegExp;
  /** A reference policy in policy-check/reference/. The principal may never get more access than this. */
  reference: string;
}

export interface IgnoredFinding {
  /** The ValidatePolicy issue code, e.g. PASS_ROLE_WITH_STAR_IN_RESOURCE. */
  issueCode: string;
  /** Matches the policy's origin, e.g. `MyStack/MyRole`. */
  origin: RegExp;
  /** Why this finding is safe to ignore. Required. */
  reason: string;
}

export interface PolicyCheckConfig {
  references: ReferenceRule[];
  /** No identity policy in the app may grant any of these, whatever the reference says. */
  neverGrant: string[];
  /** AWS managed policies a principal may attach. Their contents aren't in the template. */
  allowedManagedPolicyArns: string[];
  ignoredFindings: IgnoredFinding[];
}

export const config: PolicyCheckConfig = {
  references: [
    { principal: /^IamPolicyCi-Export\/ExportFunctionRole/, reference: 'export-function.json' },
    { principal: /^IamPolicyCi-CiRole\/PolicyCheckRole/, reference: 'policy-check-ci.json' },
  ],
  // Actions that let a principal escalate its own access, or destroy data in bulk.
  neverGrant: [
    'iam:PassRole',
    'iam:CreateAccessKey',
    'iam:CreateRole',
    'iam:AttachRolePolicy',
    'iam:PutRolePolicy',
    'iam:UpdateAssumeRolePolicy',
    'sts:AssumeRole',
    's3:DeleteBucket',
    's3:PutBucketPolicy',
    's3:PutBucketPublicAccessBlock',
    'dynamodb:DeleteTable',
    'kms:ScheduleKeyDeletion',
  ],
  // Empty on purpose: every role in this app has its permissions written out in the
  // template, so the check can see all of them.
  allowedManagedPolicyArns: [],
  ignoredFindings: [],
};
