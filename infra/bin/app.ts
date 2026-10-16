#!/usr/bin/env node
import { App, Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { CiRoleStack } from '../lib/ci-role-stack';
import { ExportStack } from '../lib/export-stack';

const app = new App();

new ExportStack(app, 'IamPolicyCi-Export');
new CiRoleStack(app, 'IamPolicyCi-CiRole', {
  githubRepo: (app.node.tryGetContext('githubRepo') as string | undefined) ?? 'InfraTales/iam-policy-ci',
  oidcProviderArn: app.node.tryGetContext('oidcProviderArn') as string | undefined,
});

// cdk-nag runs on every synth. A finding without a written acknowledgement fails `cdk synth`.
// The access-analyzer CI job synthesizes with `-c nag=false`, so a change cdk-nag rejects
// still reaches Access Analyzer instead of stopping at synth. The check job keeps cdk-nag on.
const nag: unknown = app.node.tryGetContext('nag');
if (nag !== false && nag !== 'false') {
  Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
}
