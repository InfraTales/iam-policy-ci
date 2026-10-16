import {
  AccessAnalyzerClient,
  AccessCheckResourceType,
  CheckAccessNotGrantedCommand,
  CheckNoNewAccessCommand,
  CheckNoPublicAccessCommand,
  type ReasonSummary,
  ValidatePolicyCommand,
  type ValidatePolicyFinding,
  ValidatePolicyResourceType,
} from '@aws-sdk/client-accessanalyzer';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { PolicyCheckConfig } from './config';
import type { Extraction, PolicyDocument } from './extract';

export type CheckName =
  | 'ValidatePolicy'
  | 'CheckNoNewAccess'
  | 'CheckAccessNotGranted'
  | 'CheckNoPublicAccess'
  | 'ReferenceExists'
  | 'ActionsInReference'
  | 'ManagedPolicyAllowList';

export type PolicyType = 'IDENTITY_POLICY' | 'RESOURCE_POLICY';

export interface PlannedCheck {
  check: Exclude<CheckName, 'ReferenceExists' | 'ActionsInReference' | 'ManagedPolicyAllowList'>;
  target: string;
  policyType: PolicyType;
  document: PolicyDocument;
  resourceType?: string;
  reference?: { file: string; document: PolicyDocument };
  actions?: string[];
}

export interface CheckResult {
  check: CheckName;
  target: string;
  status: 'PASS' | 'FAIL';
  messages: string[];
}

/** The custom policy checks are billed per call; ValidatePolicy isn't. See docs/cost.md. */
export const BILLED_CHECKS = new Set<CheckName>(['CheckNoNewAccess', 'CheckAccessNotGranted', 'CheckNoPublicAccess']);

/** CheckAccessNotGranted takes at most this many actions per call. */
export const MAX_ACTIONS_PER_CALL = 100;

/** ValidatePolicy findings that fail the build. WARNING and SUGGESTION are printed only. */
const BLOCKING_FINDINGS = new Set(['ERROR', 'SECURITY_WARNING']);

const VALIDATE_RESOURCE_TYPES = new Set<string>(Object.values(ValidatePolicyResourceType));
const PUBLIC_CHECK_RESOURCE_TYPES = new Set<string>(Object.values(AccessCheckResourceType));

export function loadReference(dir: string, file: string): PolicyDocument {
  return JSON.parse(readFileSync(join(dir, file), 'utf8')) as PolicyDocument;
}

/**
 * Works out which API calls to make. Also runs the checks that need no API: every
 * principal has a reference policy, grants no action its reference leaves out, and
 * attaches no managed policy we can't see.
 */
export function planChecks(
  extraction: Extraction,
  config: PolicyCheckConfig,
  referenceDir: string,
): { planned: PlannedCheck[]; local: CheckResult[] } {
  const planned: PlannedCheck[] = [];
  const local: CheckResult[] = [];

  for (const p of extraction.principals) {
    const target = `${p.stack}/${p.logicalId}`;

    for (const source of p.sources) {
      planned.push({ check: 'ValidatePolicy', target: source.origin, policyType: 'IDENTITY_POLICY', document: source.document });
    }

    const unknownManaged = p.externalManagedPolicyArns.filter((a) => !config.allowedManagedPolicyArns.includes(a));
    local.push({
      check: 'ManagedPolicyAllowList',
      target,
      status: unknownManaged.length === 0 ? 'PASS' : 'FAIL',
      messages: unknownManaged.map((a) => `attaches ${a}, which isn't in allowedManagedPolicyArns`),
    });

    const rule = config.references.find((r) => r.principal.test(target));
    if (!rule) {
      local.push({
        check: 'ReferenceExists',
        target,
        status: 'FAIL',
        messages: ['no reference policy matches this principal; add one to policy-check/config.ts'],
      });
    } else {
      local.push({ check: 'ReferenceExists', target, status: 'PASS', messages: [rule.reference] });
      const reference = loadReference(referenceDir, rule.reference);
      const extra = actionsOutsideReference(p.merged, reference);
      local.push({
        check: 'ActionsInReference',
        target,
        status: extra.length === 0 ? 'PASS' : 'FAIL',
        messages: extra.map((e) => `${e}, which ${rule.reference} doesn't allow`),
      });
      if (p.merged.Statement.length > 0) {
        planned.push({
          check: 'CheckNoNewAccess',
          target,
          policyType: 'IDENTITY_POLICY',
          document: p.merged,
          reference: { file: rule.reference, document: reference },
        });
      }
    }

    if (p.merged.Statement.length > 0) {
      for (let i = 0; i < config.neverGrant.length; i += MAX_ACTIONS_PER_CALL) {
        planned.push({
          check: 'CheckAccessNotGranted',
          target,
          policyType: 'IDENTITY_POLICY',
          document: p.merged,
          actions: config.neverGrant.slice(i, i + MAX_ACTIONS_PER_CALL),
        });
      }
    }
  }

  for (const rp of extraction.resourcePolicies) {
    const target = `${rp.origin} (${rp.resourceType})`;
    planned.push({
      check: 'ValidatePolicy',
      target,
      policyType: 'RESOURCE_POLICY',
      document: rp.document,
      resourceType: VALIDATE_RESOURCE_TYPES.has(rp.resourceType) ? rp.resourceType : undefined,
    });
    if (PUBLIC_CHECK_RESOURCE_TYPES.has(rp.resourceType)) {
      planned.push({
        check: 'CheckNoPublicAccess',
        target,
        policyType: 'RESOURCE_POLICY',
        document: rp.document,
        resourceType: rp.resourceType,
      });
    }
  }

  return { planned, local };
}

const asList = (v: unknown): string[] => (v === undefined ? [] : [v].flat().map(String));

/** IAM action globs: case-insensitive, * for any run of characters, ? for one. */
function actionGlob(pattern: string): RegExp {
  const body = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${body}$`, 'i');
}

/**
 * Offline, action-level comparison with the reference: every action an Allow statement
 * grants must match an action the reference allows. A wildcard action like `s3:*` only
 * passes if the reference allows that same wildcard or a wider one. Resources aren't
 * compared here; CheckNoNewAccess does that with AWS. NotAction can't be compared
 * offline, so it fails.
 */
export function actionsOutsideReference(policy: PolicyDocument, reference: PolicyDocument): string[] {
  const allowed = reference.Statement.filter((st) => st.Effect === 'Allow').flatMap((st) => asList(st.Action)).map(actionGlob);
  const out: string[] = [];
  policy.Statement.forEach((st, i) => {
    if (st.Effect !== 'Allow') return;
    const where = typeof st.Sid === 'string' && st.Sid !== '' ? `statement "${st.Sid}"` : `statement ${i}`;
    if (st.NotAction !== undefined) out.push(`${where} uses NotAction, which can't be compared offline`);
    for (const action of asList(st.Action)) {
      if (!allowed.some((g) => g.test(action))) out.push(`${where} grants ${action}`);
    }
  });
  return out;
}

function reasonsText(reasons: ReasonSummary[] | undefined): string[] {
  return (reasons ?? []).map((r) => {
    const where = r.statementId ? `statement "${r.statementId}"` : `statement ${r.statementIndex ?? '?'}`;
    return `${where}: ${r.description ?? 'no description'}`;
  });
}

function findingText(f: ValidatePolicyFinding): string {
  return `${f.findingType} ${f.issueCode}: ${f.findingDetails}`;
}

export async function runCheck(
  client: AccessAnalyzerClient,
  c: PlannedCheck,
  config: PolicyCheckConfig,
): Promise<CheckResult> {
  const policy = JSON.stringify(c.document);
  switch (c.check) {
    case 'ValidatePolicy': {
      const findings: ValidatePolicyFinding[] = [];
      let nextToken: string | undefined;
      do {
        const page = await client.send(
          new ValidatePolicyCommand({
            policyDocument: policy,
            policyType: c.policyType,
            validatePolicyResourceType: c.resourceType as ValidatePolicyResourceType | undefined,
            nextToken,
          }),
        );
        findings.push(...(page.findings ?? []));
        nextToken = page.nextToken;
      } while (nextToken);
      const ignored = (f: ValidatePolicyFinding) =>
        config.ignoredFindings.some((i) => i.issueCode === f.issueCode && i.origin.test(c.target));
      const blocking = findings.filter((f) => BLOCKING_FINDINGS.has(f.findingType ?? '') && !ignored(f));
      return {
        check: c.check,
        target: c.target,
        status: blocking.length === 0 ? 'PASS' : 'FAIL',
        messages: findings.map((f) => (ignored(f) ? `ignored: ${findingText(f)}` : findingText(f))),
      };
    }
    case 'CheckNoNewAccess': {
      if (!c.reference) throw new Error(`CheckNoNewAccess for ${c.target} has no reference`);
      const out = await client.send(
        new CheckNoNewAccessCommand({
          newPolicyDocument: policy,
          existingPolicyDocument: JSON.stringify(c.reference.document),
          policyType: c.policyType,
        }),
      );
      return {
        check: c.check,
        target: c.target,
        status: out.result === 'PASS' ? 'PASS' : 'FAIL',
        messages: [`compared with reference ${c.reference.file}`, out.message ?? '', ...reasonsText(out.reasons)].filter(Boolean),
      };
    }
    case 'CheckAccessNotGranted': {
      const out = await client.send(
        new CheckAccessNotGrantedCommand({
          policyDocument: policy,
          policyType: c.policyType,
          access: [{ actions: c.actions }],
        }),
      );
      return {
        check: c.check,
        target: c.target,
        status: out.result === 'PASS' ? 'PASS' : 'FAIL',
        messages: [out.message ?? '', ...reasonsText(out.reasons)].filter(Boolean),
      };
    }
    case 'CheckNoPublicAccess': {
      const out = await client.send(
        new CheckNoPublicAccessCommand({
          policyDocument: policy,
          resourceType: c.resourceType as AccessCheckResourceType,
        }),
      );
      return {
        check: c.check,
        target: c.target,
        status: out.result === 'PASS' ? 'PASS' : 'FAIL',
        messages: [out.message ?? '', ...reasonsText(out.reasons)].filter(Boolean),
      };
    }
  }
}

/** Runs the planned checks a few at a time. Any result other than PASS counts as a failure. */
export async function runChecks(
  client: AccessAnalyzerClient,
  planned: PlannedCheck[],
  config: PolicyCheckConfig,
  concurrency = 4,
): Promise<CheckResult[]> {
  const results: CheckResult[] = new Array<CheckResult>(planned.length);
  let next = 0;
  const worker = async () => {
    while (next < planned.length) {
      const i = next++;
      results[i] = await runCheck(client, planned[i] as PlannedCheck, config);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, planned.length) }, worker));
  return results;
}
