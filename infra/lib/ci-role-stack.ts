import { Duration, Stack, type StackProps, Validations } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import type { Construct } from 'constructs';

export interface CiRoleStackProps extends StackProps {
  /** owner/name of the GitHub repository that may assume the role. */
  githubRepo: string;
  /**
   * ARN of an existing GitHub OIDC provider. An account can have only one provider
   * per URL, so pass this if you already created one.
   */
  oidcProviderArn?: string;
}

/**
 * The role GitHub Actions assumes to run the policy check. It can call the four
 * IAM Access Analyzer APIs and nothing else, and only workflows on main or in pull
 * requests of one repository can assume it.
 */
export class CiRoleStack extends Stack {
  readonly role: iam.Role;

  constructor(scope: Construct, id: string, props: CiRoleStackProps) {
    super(scope, id, props);

    if (!/^[\w.-]+\/[\w.-]+$/.test(props.githubRepo)) {
      throw new Error(`githubRepo must look like owner/name, got "${props.githubRepo}"`);
    }

    const providerArn =
      props.oidcProviderArn ??
      new iam.OidcProviderNative(this, 'GitHubOidc', {
        url: 'https://token.actions.githubusercontent.com',
        clientIds: ['sts.amazonaws.com'],
      }).oidcProviderArn;

    this.role = new iam.Role(this, 'PolicyCheckRole', {
      description: 'GitHub Actions: run IAM Access Analyzer policy checks',
      maxSessionDuration: Duration.hours(1),
      assumedBy: new iam.WebIdentityPrincipal(providerArn, {
        StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' },
        // IAM refuses a GitHub trust policy without a sub condition, or with one that is only
        // a wildcard. A loose value such as repo:<org>/* would still pass, so scope it to one
        // repository's main branch and pull requests.
        StringLike: {
          'token.actions.githubusercontent.com:sub': [
            `repo:${props.githubRepo}:ref:refs/heads/main`,
            `repo:${props.githubRepo}:pull_request`,
          ],
        },
      }),
    });

    this.role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'RunPolicyChecks',
        actions: [
          'access-analyzer:ValidatePolicy',
          'access-analyzer:CheckNoNewAccess',
          'access-analyzer:CheckAccessNotGranted',
          'access-analyzer:CheckNoPublicAccess',
        ],
        resources: ['*'],
      }),
    );

    Validations.of(this.role.node.findChild('DefaultPolicy')).acknowledge({
      id: 'AwsSolutions::AwsSolutions-IAM5[Resource::*]',
      reason:
        'The four Access Analyzer actions have no resource types in the Service Authorization Reference, ' +
        'so "*" is the only resource IAM accepts for them.',
    });
  }
}
