import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  type CfnResource,
  type CfnTemplate,
  PLACEHOLDER_ACCOUNT,
  PLACEHOLDER_REGION,
  type ResolveContext,
  resolve,
  UnresolvableError,
} from './resolve';

/**
 * Finds every IAM policy in a synthesized CloudFormation template.
 *
 * Identity policies are grouped by the role, user or group they attach to, because
 * that's the access that principal really gets: the union of its inline policies,
 * the AWS::IAM::Policy resources that name it, and its managed policies.
 * Resource policies (bucket policies, trust policies, queue policies and so on) are
 * checked one by one.
 */

export interface PolicyDocument {
  Version?: string;
  Statement: Record<string, unknown>[];
}

export type PrincipalType = 'role' | 'user' | 'group';

export interface IdentityPolicySource {
  /** Where the policy came from, for error messages. */
  origin: string;
  document: PolicyDocument;
}

export interface PrincipalPolicies {
  stack: string;
  logicalId: string;
  type: PrincipalType;
  sources: IdentityPolicySource[];
  /** Managed policy ARNs that aren't defined in this template (AWS managed, or imported). */
  externalManagedPolicyArns: string[];
  /** Every statement from every source, in one document. */
  merged: PolicyDocument;
}

export interface ResourcePolicy {
  stack: string;
  /** Logical ID of the resource that holds or receives the policy. */
  logicalId: string;
  origin: string;
  /** The CloudFormation type the policy protects, e.g. AWS::S3::Bucket. */
  resourceType: string;
  document: PolicyDocument;
}

export interface Extraction {
  principals: PrincipalPolicies[];
  resourcePolicies: ResourcePolicy[];
  /** Resource types that can grant access but that this tool doesn't inspect. */
  unchecked: { stack: string; logicalId: string; type: string }[];
}

const PRINCIPAL_TYPES: Record<string, PrincipalType> = {
  'AWS::IAM::Role': 'role',
  'AWS::IAM::User': 'user',
  'AWS::IAM::Group': 'group',
};

const ATTACH_KEYS: Record<string, PrincipalType> = { Roles: 'role', Users: 'user', Groups: 'group' };

/** Resource types whose policy lives in a property of a separate resource. */
const RESOURCE_POLICY_TYPES: Record<string, { docKey: string; targetKey: string; protects: string }> = {
  'AWS::S3::BucketPolicy': { docKey: 'PolicyDocument', targetKey: 'Bucket', protects: 'AWS::S3::Bucket' },
  'AWS::SQS::QueuePolicy': { docKey: 'PolicyDocument', targetKey: 'Queues', protects: 'AWS::SQS::Queue' },
  'AWS::SNS::TopicPolicy': { docKey: 'PolicyDocument', targetKey: 'Topics', protects: 'AWS::SNS::Topic' },
  'AWS::SecretsManager::ResourcePolicy': {
    docKey: 'ResourcePolicy',
    targetKey: 'SecretId',
    protects: 'AWS::SecretsManager::Secret',
  },
};

/** Can grant access, but we don't read them yet. Listed so nobody assumes they were checked. */
const UNCHECKED_TYPES = new Set([
  'AWS::Lambda::Permission',
  'AWS::Lambda::LayerVersionPermission',
  'AWS::ECR::Repository',
  'AWS::Events::EventBusPolicy',
  'AWS::Logs::ResourcePolicy',
  'AWS::OpenSearchService::Domain',
  'AWS::ApiGateway::RestApi',
  'AWS::Glue::ResourcePolicy',
  'AWS::Backup::BackupVault',
  'AWS::EFS::FileSystem',
]);

function toDocument(value: unknown, origin: string): PolicyDocument {
  if (value === null || typeof value !== 'object') throw new UnresolvableError(`${origin}: policy is not an object`);
  const doc = value as { Version?: unknown; Statement?: unknown };
  const statements = Array.isArray(doc.Statement) ? doc.Statement : doc.Statement ? [doc.Statement] : [];
  if (statements.length === 0) throw new UnresolvableError(`${origin}: policy has no statements`);
  return {
    Version: typeof doc.Version === 'string' ? doc.Version : '2012-10-17',
    Statement: statements as Record<string, unknown>[],
  };
}

function refTarget(value: unknown): string | undefined {
  if (value && typeof value === 'object' && 'Ref' in value) {
    const r = (value).Ref;
    return typeof r === 'string' ? r : undefined;
  }
  return undefined;
}

function getAttTarget(value: unknown): string | undefined {
  if (value && typeof value === 'object' && 'Fn::GetAtt' in value) {
    const g = (value)['Fn::GetAtt'];
    if (Array.isArray(g) && typeof g[0] === 'string') return g[0];
  }
  return undefined;
}

export interface ExtractOptions {
  region?: string;
  account?: string;
  partition?: string;
}

export function extractTemplate(stackName: string, template: CfnTemplate, opts: ExtractOptions = {}): Extraction {
  const ctx: ResolveContext = {
    template,
    stackName,
    partition: opts.partition ?? 'aws',
    region: opts.region ?? PLACEHOLDER_REGION,
    account: opts.account ?? PLACEHOLDER_ACCOUNT,
  };
  const resources = template.Resources ?? {};
  const principals = new Map<string, PrincipalPolicies>();
  const resourcePolicies: ResourcePolicy[] = [];
  const unchecked: Extraction['unchecked'] = [];

  const principal = (logicalId: string, where: string): PrincipalPolicies => {
    const existing = principals.get(logicalId);
    if (existing) return existing;
    const res = resources[logicalId];
    const type = res ? PRINCIPAL_TYPES[res.Type] : undefined;
    if (!type) {
      // A policy attached to a role from another stack. We can't see its other
      // policies, so we can't check its total access. Fail rather than guess.
      throw new UnresolvableError(`${where} attaches to ${logicalId}, which isn't a role, user or group in ${stackName}`);
    }
    const created: PrincipalPolicies = {
      stack: stackName,
      logicalId,
      type,
      sources: [],
      externalManagedPolicyArns: [],
      merged: { Version: '2012-10-17', Statement: [] },
    };
    principals.set(logicalId, created);
    return created;
  };

  const attachments = (props: Record<string, unknown>, where: string): string[] => {
    const ids: string[] = [];
    for (const key of Object.keys(ATTACH_KEYS)) {
      const list = props[key];
      if (list === undefined) continue;
      if (!Array.isArray(list)) throw new UnresolvableError(`${where}.${key} is not a list`);
      for (const item of list) {
        const id = refTarget(item);
        if (!id) throw new UnresolvableError(`${where}.${key} has a value that isn't a Ref: ${JSON.stringify(item)}`);
        ids.push(id);
      }
    }
    return ids;
  };

  const sorted = Object.entries(resources).sort(([a], [b]) => a.localeCompare(b));

  // Create every principal first so policies can find them in any order.
  for (const [id, res] of sorted) {
    if (PRINCIPAL_TYPES[res.Type]) principal(id, id);
  }

  for (const [id, res] of sorted) {
    const props = res.Properties ?? {};
    const where = `${stackName}/${id}`;

    if (PRINCIPAL_TYPES[res.Type]) {
      const p = principal(id, where);
      for (const [i, inline] of (Array.isArray(props.Policies) ? props.Policies : []).entries()) {
        const doc = (inline as { PolicyDocument?: unknown }).PolicyDocument;
        p.sources.push({ origin: `${where} inline policy ${i}`, document: toDocument(resolve(doc, ctx), where) });
      }
      for (const arn of Array.isArray(props.ManagedPolicyArns) ? props.ManagedPolicyArns : []) {
        const local = refTarget(arn);
        if (local && resources[local]?.Type === 'AWS::IAM::ManagedPolicy') continue; // handled below
        const resolved = resolve(arn, ctx);
        if (typeof resolved !== 'string') throw new UnresolvableError(`${where}: managed policy ARN isn't a string`);
        p.externalManagedPolicyArns.push(resolved);
      }
      if (res.Type === 'AWS::IAM::Role') {
        resourcePolicies.push({
          stack: stackName,
          logicalId: id,
          origin: `${where} trust policy`,
          resourceType: 'AWS::IAM::AssumeRolePolicyDocument',
          document: toDocument(resolve(props.AssumeRolePolicyDocument, ctx), `${where} trust policy`),
        });
      }
      continue;
    }

    if (res.Type === 'AWS::IAM::Policy' || res.Type === 'AWS::IAM::ManagedPolicy') {
      const doc = toDocument(resolve(props.PolicyDocument, ctx), where);
      const targets = attachments(props, where);
      // A managed policy can also be attached from the principal's ManagedPolicyArns.
      if (res.Type === 'AWS::IAM::ManagedPolicy') {
        for (const [pid, pres] of sorted) {
          const arns = pres.Properties?.ManagedPolicyArns;
          if (PRINCIPAL_TYPES[pres.Type] && Array.isArray(arns) && arns.some((a) => refTarget(a) === id)) {
            targets.push(pid);
          }
        }
      }
      if (targets.length === 0) {
        throw new UnresolvableError(`${where} isn't attached to anything in this stack`);
      }
      for (const target of new Set(targets)) {
        principal(target, where).sources.push({ origin: where, document: doc });
      }
      continue;
    }

    const rp = RESOURCE_POLICY_TYPES[res.Type];
    if (rp) {
      const target = props[rp.targetKey];
      const first: unknown = Array.isArray(target) ? (target as unknown[])[0] : target;
      resourcePolicies.push({
        stack: stackName,
        logicalId: refTarget(first) ?? getAttTarget(first) ?? id,
        origin: where,
        resourceType: rp.protects,
        document: toDocument(resolve(props[rp.docKey], ctx), where),
      });
      continue;
    }

    if (res.Type === 'AWS::KMS::Key' && props.KeyPolicy !== undefined) {
      resourcePolicies.push(resourcePolicyOn(id, where, 'AWS::KMS::Key', props.KeyPolicy));
      continue;
    }
    if (res.Type === 'AWS::DynamoDB::Table' && (props.ResourcePolicy as CfnResource['Properties'])?.PolicyDocument) {
      const doc = (props.ResourcePolicy as Record<string, unknown>).PolicyDocument;
      resourcePolicies.push(resourcePolicyOn(id, where, 'AWS::DynamoDB::Table', doc));
      continue;
    }

    if (UNCHECKED_TYPES.has(res.Type)) unchecked.push({ stack: stackName, logicalId: id, type: res.Type });
  }

  function resourcePolicyOn(id: string, where: string, type: string, doc: unknown): ResourcePolicy {
    return { stack: stackName, logicalId: id, origin: where, resourceType: type, document: toDocument(resolve(doc, ctx), where) };
  }

  const list = [...principals.values()].filter((p) => p.sources.length > 0 || p.externalManagedPolicyArns.length > 0);
  for (const p of list) {
    p.merged = { Version: '2012-10-17', Statement: p.sources.flatMap((s) => s.document.Statement) };
  }
  return { principals: list, resourcePolicies, unchecked };
}

interface Manifest {
  artifacts?: Record<string, { type: string; properties?: { templateFile?: string; stackName?: string } }>;
}

/** Reads every stack template from a cloud assembly directory (cdk.out). */
export function loadAssembly(dir: string): { stackName: string; template: CfnTemplate }[] {
  const manifestPath = join(dir, 'manifest.json');
  if (!existsSync(manifestPath)) throw new Error(`No cloud assembly at ${dir}. Run "npx cdk synth" first.`);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as Manifest;
  const stacks = Object.entries(manifest.artifacts ?? {})
    .filter(([, a]) => a.type === 'aws:cloudformation:stack' && a.properties?.templateFile)
    .map(([id, a]) => ({
      stackName: a.properties?.stackName ?? id,
      template: JSON.parse(readFileSync(join(dir, a.properties?.templateFile as string), 'utf8')) as CfnTemplate,
    }));
  if (stacks.length === 0) throw new Error(`No stacks in ${dir}`);
  return stacks;
}

export function mergeExtractions(parts: Extraction[]): Extraction {
  return {
    principals: parts.flatMap((p) => p.principals),
    resourcePolicies: parts.flatMap((p) => p.resourcePolicies),
    unchecked: parts.flatMap((p) => p.unchecked),
  };
}
