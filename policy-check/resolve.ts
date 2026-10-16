/**
 * Turns CloudFormation intrinsic functions inside a policy into plain strings.
 *
 * IAM Access Analyzer needs a real policy document, but a synthesized CDK template is
 * full of Ref, Fn::GetAtt and Fn::Join. We replace each one with a placeholder that has
 * the right shape: an S3 bucket ARN looks like an S3 bucket ARN, in a fixed placeholder
 * account (123456789012) and Region. Reference policies match those placeholders.
 *
 * Anything we don't know how to resolve throws. A policy we can't read is a policy we
 * can't check, so the run fails instead of skipping it.
 */

export interface CfnResource {
  Type: string;
  Properties?: Record<string, unknown>;
  Metadata?: Record<string, unknown>;
}

export interface CfnTemplate {
  Resources?: Record<string, CfnResource>;
  Parameters?: Record<string, { Default?: unknown }>;
}

export interface ResolveContext {
  template: CfnTemplate;
  stackName: string;
  partition: string;
  region: string;
  account: string;
}

export const PLACEHOLDER_ACCOUNT = '123456789012';
export const PLACEHOLDER_REGION = 'us-east-1';

export class UnresolvableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnresolvableError';
  }
}

/** Marks a value removed by AWS::NoValue. */
const NO_VALUE = Symbol('AWS::NoValue');

export function resolve(value: unknown, ctx: ResolveContext): unknown {
  const out = resolveInner(value, ctx);
  if (out === NO_VALUE) throw new UnresolvableError('AWS::NoValue at the top level of a policy');
  return out;
}

function resolveInner(value: unknown, ctx: ResolveContext): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    return value.map((v) => resolveInner(v, ctx)).filter((v) => v !== NO_VALUE);
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length === 1) {
    const key = keys[0] as string;
    const arg = obj[key];
    switch (key) {
      case 'Ref':
        return ref(asString(arg, 'Ref'), ctx);
      case 'Fn::GetAtt':
        return getAtt(arg, ctx);
      case 'Fn::Join':
        return join(arg, ctx);
      case 'Fn::Sub':
        return sub(arg, ctx);
      case 'Fn::Select':
        return select(arg, ctx);
      case 'Fn::Split':
        return split(arg, ctx);
      default:
        if (key.startsWith('Fn::')) {
          throw new UnresolvableError(`${key} is not supported in policies (found in ${ctx.stackName})`);
        }
    }
  }
  const result: Record<string, unknown> = {};
  for (const k of keys) {
    const v = resolveInner(obj[k], ctx);
    if (v !== NO_VALUE) result[k] = v;
  }
  return result;
}

function asString(v: unknown, where: string): string {
  if (typeof v !== 'string') throw new UnresolvableError(`${where} expects a string, got ${JSON.stringify(v)}`);
  return v;
}

function resolveToString(v: unknown, ctx: ResolveContext, where: string): string {
  const r = resolveInner(v, ctx);
  if (typeof r !== 'string') throw new UnresolvableError(`${where} did not resolve to a string: ${JSON.stringify(r)}`);
  return r;
}

function pseudo(name: string, ctx: ResolveContext): string | typeof NO_VALUE | undefined {
  switch (name) {
    case 'AWS::Partition':
      return ctx.partition;
    case 'AWS::Region':
      return ctx.region;
    case 'AWS::AccountId':
      return ctx.account;
    case 'AWS::StackName':
      return ctx.stackName;
    case 'AWS::URLSuffix':
      return 'amazonaws.com';
    case 'AWS::NoValue':
      return NO_VALUE;
    default:
      return undefined;
  }
}

function resourceOf(logicalId: string, ctx: ResolveContext): CfnResource {
  const res = ctx.template.Resources?.[logicalId];
  if (!res) throw new UnresolvableError(`Unknown logical ID ${logicalId} in ${ctx.stackName}`);
  return res;
}

const NAME_PROPERTY: Record<string, string> = {
  'AWS::S3::Bucket': 'BucketName',
  'AWS::DynamoDB::Table': 'TableName',
  'AWS::DynamoDB::GlobalTable': 'TableName',
  'AWS::IAM::Role': 'RoleName',
  'AWS::IAM::User': 'UserName',
  'AWS::IAM::Group': 'GroupName',
  'AWS::IAM::Policy': 'PolicyName',
  'AWS::IAM::ManagedPolicy': 'ManagedPolicyName',
  'AWS::Lambda::Function': 'FunctionName',
  'AWS::Logs::LogGroup': 'LogGroupName',
  'AWS::SQS::Queue': 'QueueName',
  'AWS::SNS::Topic': 'TopicName',
};

/** The physical name we pretend CloudFormation gave the resource. */
export function placeholderName(logicalId: string, ctx: ResolveContext): string {
  const res = resourceOf(logicalId, ctx);
  const prop = NAME_PROPERTY[res.Type];
  const explicit = prop ? res.Properties?.[prop] : undefined;
  if (explicit !== undefined) return resolveToString(explicit, ctx, `${logicalId}.${prop}`);
  // S3 bucket names must be lowercase.
  return res.Type === 'AWS::S3::Bucket' ? logicalId.toLowerCase() : logicalId;
}

function arnFor(logicalId: string, ctx: ResolveContext): string {
  const res = resourceOf(logicalId, ctx);
  const name = placeholderName(logicalId, ctx);
  const { partition: p, region: r, account: a } = ctx;
  switch (res.Type) {
    case 'AWS::S3::Bucket':
      return `arn:${p}:s3:::${name}`;
    case 'AWS::DynamoDB::Table':
    case 'AWS::DynamoDB::GlobalTable':
      return `arn:${p}:dynamodb:${r}:${a}:table/${name}`;
    case 'AWS::IAM::Role':
      return `arn:${p}:iam::${a}:role/${name}`;
    case 'AWS::IAM::User':
      return `arn:${p}:iam::${a}:user/${name}`;
    case 'AWS::IAM::Group':
      return `arn:${p}:iam::${a}:group/${name}`;
    case 'AWS::IAM::ManagedPolicy':
      return `arn:${p}:iam::${a}:policy/${name}`;
    case 'AWS::IAM::OIDCProvider': {
      const url = resolveToString(res.Properties?.Url, ctx, `${logicalId}.Url`);
      return `arn:${p}:iam::${a}:oidc-provider/${url.replace(/^https:\/\//, '')}`;
    }
    case 'AWS::Lambda::Function':
      return `arn:${p}:lambda:${r}:${a}:function:${name}`;
    case 'AWS::Logs::LogGroup':
      // Fn::GetAtt LogGroup.Arn really does end in ":*".
      return `arn:${p}:logs:${r}:${a}:log-group:${name}:*`;
    case 'AWS::SQS::Queue':
      return `arn:${p}:sqs:${r}:${a}:${name}`;
    case 'AWS::SNS::Topic':
      return `arn:${p}:sns:${r}:${a}:${name}`;
    case 'AWS::KMS::Key':
      return `arn:${p}:kms:${r}:${a}:key/${logicalId}`;
    default:
      throw new UnresolvableError(`No placeholder ARN for ${res.Type} (${logicalId})`);
  }
}

function ref(name: string, ctx: ResolveContext): unknown {
  const p = pseudo(name, ctx);
  if (p !== undefined) return p;
  const param = ctx.template.Parameters?.[name];
  if (param) {
    if (param.Default === undefined) throw new UnresolvableError(`Parameter ${name} has no default`);
    return param.Default;
  }
  const res = resourceOf(name, ctx);
  switch (res.Type) {
    case 'AWS::S3::Bucket':
    case 'AWS::DynamoDB::Table':
    case 'AWS::DynamoDB::GlobalTable':
    case 'AWS::IAM::Role':
    case 'AWS::IAM::User':
    case 'AWS::IAM::Group':
    case 'AWS::IAM::Policy':
    case 'AWS::Lambda::Function':
    case 'AWS::Logs::LogGroup':
      return placeholderName(name, ctx);
    case 'AWS::IAM::ManagedPolicy':
    case 'AWS::IAM::OIDCProvider':
    case 'AWS::SNS::Topic':
      return arnFor(name, ctx);
    case 'AWS::SQS::Queue':
      return `https://sqs.${ctx.region}.amazonaws.com/${ctx.account}/${placeholderName(name, ctx)}`;
    case 'AWS::KMS::Key':
      return name;
    default:
      throw new UnresolvableError(`Ref to ${res.Type} (${name}) is not supported`);
  }
}

function getAtt(arg: unknown, ctx: ResolveContext): string {
  let logicalId: string;
  let attr: string;
  if (typeof arg === 'string') {
    const dot = arg.indexOf('.');
    logicalId = arg.slice(0, dot);
    attr = arg.slice(dot + 1);
  } else if (Array.isArray(arg) && arg.length === 2) {
    logicalId = asString(arg[0], 'Fn::GetAtt');
    attr = resolveToString(arg[1], ctx, 'Fn::GetAtt attribute');
  } else {
    throw new UnresolvableError(`Bad Fn::GetAtt ${JSON.stringify(arg)}`);
  }
  const res = resourceOf(logicalId, ctx);
  if (attr === 'Arn') return arnFor(logicalId, ctx);
  if ((res.Type === 'AWS::DynamoDB::Table' || res.Type === 'AWS::DynamoDB::GlobalTable') && attr === 'StreamArn') {
    return `${arnFor(logicalId, ctx)}/stream/1970-01-01T00:00:00.000`;
  }
  if (res.Type === 'AWS::SQS::Queue' && attr === 'QueueName') return placeholderName(logicalId, ctx);
  throw new UnresolvableError(`Fn::GetAtt ${logicalId}.${attr} (${res.Type}) is not supported`);
}

function join(arg: unknown, ctx: ResolveContext): string {
  if (!Array.isArray(arg) || arg.length !== 2) throw new UnresolvableError('Fn::Join expects [delimiter, list]');
  const delimiter = asString(arg[0], 'Fn::Join delimiter');
  const list = resolveInner(arg[1], ctx);
  if (!Array.isArray(list)) throw new UnresolvableError('Fn::Join list did not resolve to a list');
  return list.map((v) => asString(v, 'Fn::Join item')).join(delimiter);
}

function sub(arg: unknown, ctx: ResolveContext): string {
  let template: string;
  let vars: Record<string, unknown> = {};
  if (typeof arg === 'string') {
    template = arg;
  } else if (Array.isArray(arg) && arg.length === 2) {
    template = asString(arg[0], 'Fn::Sub');
    vars = (arg[1] ?? {}) as Record<string, unknown>;
  } else {
    throw new UnresolvableError('Fn::Sub expects a string or [string, vars]');
  }
  return template.replace(/\$\{([^}]+)\}/g, (_m, expr: string) => {
    if (expr.startsWith('!')) return `\${${expr.slice(1)}}`;
    if (expr in vars) return resolveToString(vars[expr], ctx, `Fn::Sub var ${expr}`);
    if (expr.includes('.') && !expr.startsWith('AWS::')) return getAtt(expr, ctx);
    return resolveToString({ Ref: expr }, ctx, `Fn::Sub \${${expr}}`);
  });
}

function select(arg: unknown, ctx: ResolveContext): unknown {
  if (!Array.isArray(arg) || arg.length !== 2) throw new UnresolvableError('Fn::Select expects [index, list]');
  const index = Number(resolveInner(arg[0], ctx));
  const list = resolveInner(arg[1], ctx);
  if (!Array.isArray(list) || !Number.isInteger(index) || index < 0 || index >= list.length) {
    throw new UnresolvableError('Fn::Select index out of range');
  }
  return list[index];
}

function split(arg: unknown, ctx: ResolveContext): string[] {
  if (!Array.isArray(arg) || arg.length !== 2) throw new UnresolvableError('Fn::Split expects [delimiter, string]');
  const delimiter = asString(arg[0], 'Fn::Split delimiter');
  return resolveToString(arg[1], ctx, 'Fn::Split source').split(delimiter);
}
