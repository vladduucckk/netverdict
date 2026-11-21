import { cidrCovers, ipInCidr, ipToInt, ipsInCidr, parseCidr } from "./ip";
import type {
  Action,
  Chain,
  CtState,
  Direction,
  Match,
  Packet,
  Policy,
  Proto,
  Rule,
  Verdict,
} from "./policy";

export type TraceStep = {
  chain: string;
  rule: Rule;
  matched: boolean;
  skippedReason?: string;
  effect?: "accept" | "drop" | "reject" | "jump" | "return" | "continue";
  jumpTo?: string;
};

export type ProbeResult = {
  verdict: Verdict;
  chain: string;
  table: string;
  matchedRule: Rule | null;
  matchedChain: string | null;
  path: TraceStep[];
  reason: string;
  policyFallback: boolean;
  depth: number;
};

function matchRule(match: Match, packet: Packet): { ok: boolean; reason?: string } {
  if (match.any) return { ok: true };

  if (match.iif && match.iif !== packet.iif) {
    return { ok: false, reason: `iif ${packet.iif} ≠ ${match.iif}` };
  }
  if (match.oif && match.oif !== packet.oif) {
    return { ok: false, reason: `oif ${packet.oif} ≠ ${match.oif}` };
  }
  if (match.proto && match.proto !== packet.proto) {
    return { ok: false, reason: `proto ${packet.proto} ≠ ${match.proto}` };
  }
  if (match.dport !== undefined && match.dport !== packet.dport) {
    return { ok: false, reason: `dport ${packet.dport} ≠ ${match.dport}` };
  }
  if (match.sport !== undefined && match.sport !== packet.sport) {
    return { ok: false, reason: `sport ${packet.sport} ≠ ${match.sport}` };
  }
  if (match.saddrCidr && !ipInCidr(packet.src.trim(), match.saddrCidr)) {
    return { ok: false, reason: `src ${packet.src} ∉ ${match.saddrCidr}` };
  }
  if (match.daddrCidr && !ipInCidr(packet.dst.trim(), match.daddrCidr)) {
    return { ok: false, reason: `dst ${packet.dst} ∉ ${match.daddrCidr}` };
  }
  if (match.ctState && !match.ctState.includes(packet.ctState)) {
    return {
      ok: false,
      reason: `ct state ${packet.ctState} not in [${match.ctState.join(",")}]`,
    };
  }
  return { ok: true };
}

function formatMatch(match: Match): string {
  if (match.any) return "all";
  const parts: string[] = [];
  if (match.iif) parts.push(`iif ${match.iif}`);
  if (match.oif) parts.push(`oif ${match.oif}`);
  if (match.ctState) parts.push(`ct state ${match.ctState.join(",")}`);
  if (match.proto) parts.push(match.proto);
  if (match.saddrCidr) parts.push(`ip saddr ${match.saddrCidr}`);
  if (match.daddrCidr) parts.push(`ip daddr ${match.daddrCidr}`);
  if (match.sport !== undefined) parts.push(`sport ${match.sport}`);
  if (match.dport !== undefined) parts.push(`dport ${match.dport}`);
  return parts.join("  ") || "true";
}

export function ruleExpression(rule: Rule): string {
  const target =
    rule.action === "jump" && rule.jump ? `jump ${rule.jump}` : rule.action;
  return `${formatMatch(rule.match)}  ${target}`;
}

function findChain(policy: Policy, name: string): Chain | undefined {
  return policy.chains.find((c) => c.name === name);
}

function isTerminating(action: Action): action is "accept" | "drop" | "reject" {
  return action === "accept" || action === "drop" || action === "reject";
}

const MAX_DEPTH = 32;

function syntheticRule(id: string, comment: string, action: Action): Rule {
  return { id, comment, match: { any: true }, action };
}

function walkChain(
  policy: Policy,
  chain: Chain,
  packet: Packet,
  path: TraceStep[],
  depth: number,
): {
  verdict: Verdict | null;
  matchedRule: Rule | null;
  matchedChain: string | null;
  returned: boolean;
} {
  if (depth >= MAX_DEPTH) {
    const rule = syntheticRule(
      "engine:max-depth",
      `jump depth exceeded (${MAX_DEPTH})`,
      "drop",
    );
    path.push({
      chain: chain.name,
      rule,
      matched: true,
      effect: "drop",
    });
    return {
      verdict: "drop",
      matchedRule: rule,
      matchedChain: chain.name,
      returned: false,
    };
  }

  for (const rule of chain.rules) {
    const result = matchRule(rule.match, packet);
    if (!result.ok) {
      path.push({
        chain: chain.name,
        rule,
        matched: false,
        skippedReason: result.reason,
      });
      continue;
    }

    if (rule.action === "continue") {
      path.push({
        chain: chain.name,
        rule,
        matched: true,
        effect: "continue",
      });
      continue;
    }

    if (rule.action === "return") {
      path.push({
        chain: chain.name,
        rule,
        matched: true,
        effect: "return",
      });
      return {
        verdict: null,
        matchedRule: rule,
        matchedChain: chain.name,
        returned: true,
      };
    }

    if (rule.action === "jump") {
      const targetName = rule.jump?.trim();
      path.push({
        chain: chain.name,
        rule,
        matched: true,
        effect: "jump",
        jumpTo: targetName,
      });

      if (!targetName) {
        const missing = syntheticRule(
          "engine:jump-missing-target",
          "jump rule has no target chain",
          "drop",
        );
        path.push({
          chain: chain.name,
          rule: missing,
          matched: true,
          effect: "drop",
        });
        return {
          verdict: "drop",
          matchedRule: missing,
          matchedChain: chain.name,
          returned: false,
        };
      }

      const target = findChain(policy, targetName);
      if (!target) {
        const missing = syntheticRule(
          `engine:missing:${targetName}`,
          `jump target chain "${targetName}" does not exist`,
          "drop",
        );
        path.push({
          chain: chain.name,
          rule: missing,
          matched: true,
          effect: "drop",
        });
        return {
          verdict: "drop",
          matchedRule: missing,
          matchedChain: chain.name,
          returned: false,
        };
      }

      const nested = walkChain(policy, target, packet, path, depth + 1);
      if (nested.returned) {
        // nftables: return from user chain resumes after the jump
        continue;
      }
      if (nested.verdict) {
        return nested;
      }
      // User chains have no hook policy — implicit return to caller
      continue;
    }

    if (isTerminating(rule.action)) {
      path.push({
        chain: chain.name,
        rule,
        matched: true,
        effect: rule.action,
      });
      return {
        verdict: rule.action,
        matchedRule: rule,
        matchedChain: chain.name,
        returned: false,
      };
    }
  }

  return {
    verdict: null,
    matchedRule: null,
    matchedChain: null,
    returned: false,
  };
}

/** Normalize packet fields the evaluator relies on (trim IPs). */
export function normalizePacket(packet: Packet): Packet {
  return {
    ...packet,
    src: packet.src.trim(),
    dst: packet.dst.trim(),
    iif: packet.iif.trim(),
    oif: packet.oif.trim(),
  };
}

/** Base chain selected by its hook, not by its name. */
export function resolveHookChain(
  policy: Policy,
  direction: Direction,
): Chain | undefined {
  return policy.chains.find((chain) => chain.hook === direction);
}

export function probe(policy: Policy, packet: Packet): ProbeResult {
  const normalized = normalizePacket(packet);
  const chain = resolveHookChain(policy, normalized.direction);
  if (!chain) {
    const hookName = normalized.direction.toUpperCase();
    return {
      verdict: "drop",
      chain: hookName,
      table: policy.table,
      matchedRule: null,
      matchedChain: null,
      path: [],
      reason: `No base chain hooked to ${normalized.direction}`,
      policyFallback: true,
      depth: 0,
    };
  }

  const path: TraceStep[] = [];
  const outcome = walkChain(policy, chain, normalized, path, 0);

  if (outcome.verdict) {
    const rule = outcome.matchedRule;
    return {
      verdict: outcome.verdict,
      chain: chain.name,
      table: policy.table,
      matchedRule: rule,
      matchedChain: outcome.matchedChain,
      path,
      reason: rule
        ? `Matched ${rule.id} in ${outcome.matchedChain}: ${rule.comment}`
        : `Verdict ${outcome.verdict}`,
      policyFallback: false,
      depth: path.filter((s) => s.effect === "jump").length,
    };
  }

  // Only base (hook) chains apply chain policy; this is always a hook chain here.
  return {
    verdict: chain.policy,
    chain: chain.name,
    table: policy.table,
    matchedRule: null,
    matchedChain: chain.name,
    path,
    reason: `Fell through to chain policy (${chain.policy})`,
    policyFallback: true,
    depth: path.filter((s) => s.effect === "jump").length,
  };
}

function shellArg(value: string | number): string {
  const text = String(value);
  if (/^[A-Za-z0-9_.:@/+-]+$/.test(text)) return text;
  return `'${text.replace(/'/g, `'\\''`)}'`;
}

export function formatCli(packet: Packet): string {
  const p = normalizePacket(packet);
  return [
    "netverdict probe",
    `--src ${shellArg(p.src)}`,
    `--dst ${shellArg(p.dst)}`,
    `--sport ${shellArg(p.sport)}`,
    `--dport ${shellArg(p.dport)}`,
    `--proto ${shellArg(p.proto)}`,
    `--iif ${shellArg(p.iif)}`,
    `--oif ${shellArg(p.oif)}`,
    `--dir ${shellArg(p.direction)}`,
    `--ct ${shellArg(p.ctState)}`,
  ].join(" ");
}

/**
 * Conservative: A covers B if every packet matching B also matches A.
 * Used for shadow detection between terminating rules.
 */
function constraintKeys(match: Match): string[] {
  const keys: string[] = [];
  if (match.any) keys.push("any");
  if (match.iif) keys.push("iif");
  if (match.oif) keys.push("oif");
  if (match.proto) keys.push("proto");
  if (match.sport !== undefined) keys.push("sport");
  if (match.dport !== undefined) keys.push("dport");
  if (match.saddrCidr) keys.push("saddr");
  if (match.daddrCidr) keys.push("daddr");
  if (match.ctState) keys.push("ctState");
  return keys;
}

function matchesEverything(match: Match): boolean {
  if (match.any) return true;
  return constraintKeys(match).length === 0;
}

export function matchCovers(outer: Match, inner: Match): boolean {
  if (matchesEverything(outer)) return true;
  if (matchesEverything(inner)) return false;

  if (outer.iif && outer.iif !== inner.iif) return false;
  if (outer.oif && outer.oif !== inner.oif) return false;
  if (outer.proto && outer.proto !== inner.proto) return false;
  if (outer.dport !== undefined && outer.dport !== inner.dport) return false;
  if (outer.sport !== undefined && outer.sport !== inner.sport) return false;

  if (!cidrCovers(outer.saddrCidr, inner.saddrCidr)) return false;
  if (!cidrCovers(outer.daddrCidr, inner.daddrCidr)) return false;

  if (outer.ctState) {
    // An empty state list matches nothing, so it covers nothing.
    if (outer.ctState.length === 0) return false;
    if (!inner.ctState || inner.ctState.length === 0) return false;
    if (!inner.ctState.every((s) => outer.ctState!.includes(s))) return false;
  }

  return true;
}

export type AuditFinding = {
  id: string;
  severity: "error" | "warn" | "info";
  kind: "shadow" | "duplicate" | "broad-accept" | "smell";
  chain: string;
  ruleId: string;
  relatedRuleId?: string;
  title: string;
  detail: string;
  /** Packet that demonstrates the finding, when one exists. */
  sample?: Packet;
};

function matchFingerprint(match: Match): string {
  return JSON.stringify({
    any: match.any ?? false,
    iif: match.iif ?? null,
    oif: match.oif ?? null,
    proto: match.proto ?? null,
    sport: match.sport ?? null,
    dport: match.dport ?? null,
    saddrCidr: match.saddrCidr ?? null,
    daddrCidr: match.daddrCidr ?? null,
    ctState: match.ctState ? [...match.ctState].sort() : null,
  });
}

const DEFAULT_SRC = [
  "10.0.0.1",
  "10.0.2.15",
  "10.0.4.12",
  "127.0.0.1",
  "203.0.113.50",
  "198.51.100.9",
];
const DEFAULT_DST = [
  "10.0.1.10",
  "10.0.1.20",
  "10.0.1.53",
  "127.0.0.1",
  "198.51.100.10",
  "1.1.1.1",
];
const DEFAULT_PORTS = [0, 9, 22, 53, 80, 443, 5432, 9100];

function unique<T>(values: T[]): T[] {
  const out: T[] = [];
  for (const value of values) {
    if (!out.includes(value)) out.push(value);
  }
  return out;
}

function ipChoices(cidr: string | undefined, defaults: string[]): string[] {
  if (!cidr) return defaults;
  if (!parseCidr(cidr)) return [];
  return unique([
    ...ipsInCidr(cidr),
    ...defaults.filter((ip) => ipInCidr(ip, cidr)),
  ]);
}

function ipInBoth(
  a: string | undefined,
  b: string | undefined,
  defaults: string[],
): string | null {
  const pool = unique([
    ...(a ? ipsInCidr(a) : []),
    ...(b ? ipsInCidr(b) : []),
    ...defaults,
  ]);
  const hit = pool.find(
    (ip) => (!a || ipInCidr(ip, a)) && (!b || ipInCidr(ip, b)),
  );
  return hit ?? null;
}

/** One concrete packet that satisfies `match`, or null if the match is impossible. */
export function synthesizePacket(
  match: Match,
  direction: Packet["direction"] = "input",
): Packet | null {
  if (match.ctState && match.ctState.length === 0) return null;
  const src = ipChoices(match.saddrCidr, DEFAULT_SRC)[0];
  const dst = ipChoices(match.daddrCidr, DEFAULT_DST)[0];
  if (!src || !dst) return null;
  const proto = match.proto ?? "tcp";
  const packet: Packet = {
    src,
    dst,
    sport: match.sport ?? 40000,
    dport: match.dport ?? (proto === "icmp" ? 0 : 9),
    proto,
    iif: match.iif ?? "eth0",
    oif: match.oif ?? "eth0",
    direction,
    ctState: match.ctState?.[0] ?? "new",
  };
  return matchRule(match, packet).ok ? packet : null;
}

/**
 * Bounded packets that satisfy a match. Used to prove a rule is still reachable.
 * Failure to find a hit is inconclusive — only a superset cover is a proof of shadow.
 */
export function candidatePackets(
  match: Match,
  direction: Packet["direction"] = "input",
): Packet[] {
  if (match.ctState && match.ctState.length === 0) return [];
  const srcs = ipChoices(match.saddrCidr, DEFAULT_SRC).slice(0, 6);
  const dsts = ipChoices(match.daddrCidr, DEFAULT_DST).slice(0, 6);
  const protos: Proto[] = match.proto ? [match.proto] : ["tcp", "udp", "icmp"];
  const sports = match.sport !== undefined ? [match.sport] : [40000];
  const dports =
    match.dport !== undefined
      ? [match.dport]
      : protos.length === 1 && protos[0] === "icmp"
        ? [0]
        : DEFAULT_PORTS;
  const iifs = match.iif ? [match.iif] : ["eth0", "lo"];
  const oifs = match.oif ? [match.oif] : ["eth0"];
  const states: CtState[] = match.ctState?.length
    ? match.ctState
    : ["new", "established", "related", "invalid"];
  if (srcs.length === 0 || dsts.length === 0) return [];

  const packets: Packet[] = [];
  const cap = 512;
  for (const src of srcs) {
    for (const dst of dsts) {
      for (const proto of protos) {
        for (const sport of sports) {
          for (const dport of dports) {
            for (const iif of iifs) {
              for (const oif of oifs) {
                for (const ctState of states) {
                  const packet: Packet = {
                    src,
                    dst,
                    sport,
                    dport,
                    proto,
                    iif,
                    oif,
                    direction,
                    ctState,
                  };
                  if (!matchRule(match, packet).ok) continue;
                  packets.push(packet);
                  if (packets.length >= cap) return packets;
                }
              }
            }
          }
        }
      }
    }
  }
  return packets;
}

function intersectPacket(
  later: Match,
  earlier: Match,
  direction: Direction,
): Packet | null {
  if (later.any) return synthesizePacket(earlier, direction);
  if (earlier.any) return synthesizePacket(later, direction);
  if (
    (later.ctState && later.ctState.length === 0) ||
    (earlier.ctState && earlier.ctState.length === 0)
  ) {
    return null;
  }

  const agree = <T>(a: T | undefined, b: T | undefined): T | undefined | null => {
    if (a !== undefined && b !== undefined && a !== b) return null;
    return a ?? b;
  };
  const proto = agree(later.proto, earlier.proto);
  const sport = agree(later.sport, earlier.sport);
  const dport = agree(later.dport, earlier.dport);
  const iif = agree(later.iif, earlier.iif);
  const oif = agree(later.oif, earlier.oif);
  if (proto === null || sport === null || dport === null || iif === null || oif === null) {
    return null;
  }

  let ctState: CtState = "new";
  if (later.ctState || earlier.ctState) {
    const left = later.ctState ?? earlier.ctState!;
    const right = earlier.ctState ?? later.ctState!;
    const both = left.filter((state) => right.includes(state));
    if (both.length === 0) return null;
    ctState = both[0]!;
  }

  const src = ipInBoth(later.saddrCidr, earlier.saddrCidr, DEFAULT_SRC);
  const dst = ipInBoth(later.daddrCidr, earlier.daddrCidr, DEFAULT_DST);
  if (!src || !dst) return null;

  const resolvedProto = proto ?? "tcp";
  const packet: Packet = {
    src,
    dst,
    sport: sport ?? 40000,
    dport: dport ?? (resolvedProto === "icmp" ? 0 : 9),
    proto: resolvedProto,
    iif: iif ?? "eth0",
    oif: oif ?? "eth0",
    direction,
    ctState,
  };
  if (!matchRule(later, packet).ok || !matchRule(earlier, packet).ok) return null;
  return packet;
}

/** Effect that stops later rules in the same chain. A broken jump drops. */
function terminalAction(rule: Rule, policy: Policy): Action | null {
  if (
    rule.action === "accept" ||
    rule.action === "drop" ||
    rule.action === "reject" ||
    rule.action === "return"
  ) {
    return rule.action;
  }
  if (rule.action === "jump") {
    const target = rule.jump?.trim();
    if (!target || !findChain(policy, target)) return "drop";
  }
  return null;
}

function isBoilerplateGuard(rule: Rule): boolean {
  const keys = constraintKeys(rule.match).filter((key) => key !== "any");
  if (rule.match.any) return false;
  if (keys.length === 1 && keys[0] === "ctState") return true;
  if (
    keys.length === 1 &&
    keys[0] === "iif" &&
    rule.match.iif === "lo" &&
    rule.action === "accept"
  ) {
    return true;
  }
  return false;
}

function firstReachingPacket(
  policy: Policy,
  chain: Chain,
  rule: Rule,
): Packet | null {
  if (!chain.hook) return null;
  for (const sample of candidatePackets(rule.match, chain.hook)) {
    const result = probe(policy, sample);
    if (result.matchedRule?.id === rule.id && result.verdict === rule.action) {
      return sample;
    }
  }
  return null;
}

function validPort(port: number | undefined): boolean {
  return port === undefined || (Number.isInteger(port) && port >= 0 && port <= 65535);
}

export function auditPolicy(policy: Policy): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const seen = new Set<string>();

  const push = (finding: AuditFinding) => {
    if (seen.has(finding.id)) return;
    seen.add(finding.id);
    findings.push(finding);
  };

  const chainNames = new Set<string>();
  const ruleIds = new Map<string, string>();
  const hooks = new Map<string, string>();

  for (const chain of policy.chains) {
    if (chainNames.has(chain.name)) {
      push({
        id: `chain:${chain.name}:dup`,
        severity: "error",
        kind: "smell",
        chain: chain.name,
        ruleId: "(chain)",
        title: "Duplicate chain name",
        detail: `More than one chain is named ${chain.name}.`,
      });
    }
    chainNames.add(chain.name);

    if (chain.hook) {
      const previous = hooks.get(chain.hook);
      if (previous) {
        push({
          id: `hook:${chain.hook}:dup`,
          severity: "warn",
          kind: "smell",
          chain: chain.name,
          ruleId: "(hook)",
          relatedRuleId: previous,
          title: "Duplicate hook",
          detail: `${chain.name} and ${previous} both hook ${chain.hook}. Probe uses the first one.`,
        });
      } else {
        hooks.set(chain.hook, chain.name);
      }
    }

    for (const rule of chain.rules) {
      const owner = ruleIds.get(rule.id);
      if (owner) {
        push({
          id: `rule:${rule.id}:dup`,
          severity: "warn",
          kind: "smell",
          chain: chain.name,
          ruleId: rule.id,
          relatedRuleId: owner,
          title: "Duplicate rule id",
          detail: `${rule.id} is also used in ${owner}. Traces become ambiguous.`,
        });
      } else {
        ruleIds.set(rule.id, chain.name);
      }

      if (rule.match.saddrCidr && !parseCidr(rule.match.saddrCidr)) {
        push({
          id: `${chain.name}:${rule.id}:bad-saddr`,
          severity: "error",
          kind: "smell",
          chain: chain.name,
          ruleId: rule.id,
          title: "Invalid source CIDR",
          detail: `${rule.id} has saddr ${rule.match.saddrCidr}, which does not parse. The rule can never match.`,
        });
      }
      if (rule.match.daddrCidr && !parseCidr(rule.match.daddrCidr)) {
        push({
          id: `${chain.name}:${rule.id}:bad-daddr`,
          severity: "error",
          kind: "smell",
          chain: chain.name,
          ruleId: rule.id,
          title: "Invalid destination CIDR",
          detail: `${rule.id} has daddr ${rule.match.daddrCidr}, which does not parse. The rule can never match.`,
        });
      }
      if (!validPort(rule.match.sport) || !validPort(rule.match.dport)) {
        push({
          id: `${chain.name}:${rule.id}:bad-port`,
          severity: "error",
          kind: "smell",
          chain: chain.name,
          ruleId: rule.id,
          title: "Port out of range",
          detail: `${rule.id} uses a port outside 0–65535.`,
        });
      }
      if (rule.match.ctState && rule.match.ctState.length === 0) {
        push({
          id: `${chain.name}:${rule.id}:empty-ct`,
          severity: "error",
          kind: "smell",
          chain: chain.name,
          ruleId: rule.id,
          title: "Empty conntrack match",
          detail: `${rule.id} lists no conntrack states, so it matches nothing.`,
        });
      }
    }

    for (let i = 0; i < chain.rules.length; i++) {
      const earlier = chain.rules[i]!;

      if (
        earlier.action === "accept" &&
        matchesEverything(earlier.match) &&
        i < chain.rules.length - 1
      ) {
        push({
          id: `${chain.name}:${earlier.id}:broad`,
          severity: "warn",
          kind: "broad-accept",
          chain: chain.name,
          ruleId: earlier.id,
          title: "Accept-all before later rules",
          detail: `${earlier.id} accepts everything; rules below never run.`,
        });
      }

      const terminal = terminalAction(earlier, policy);
      if (!terminal) continue;

      for (let j = i + 1; j < chain.rules.length; j++) {
        const later = chain.rules[j]!;
        const same =
          matchFingerprint(earlier.match) === matchFingerprint(later.match);

        if (same) {
          push({
            id: `${chain.name}:${later.id}:dup`,
            severity: "warn",
            kind: "duplicate",
            chain: chain.name,
            ruleId: later.id,
            relatedRuleId: earlier.id,
            title: "Duplicate match",
            detail: `${later.id} repeats the same match as ${earlier.id}.`,
          });
          continue;
        }

        if (matchCovers(earlier.match, later.match)) {
          const negated =
            earlier.match.saddrCidr?.startsWith("!") ||
            earlier.match.daddrCidr?.startsWith("!");
          push({
            id: `${chain.name}:${later.id}:shadow:${earlier.id}`,
            severity: "error",
            kind: "shadow",
            chain: chain.name,
            ruleId: later.id,
            relatedRuleId: earlier.id,
            title: negated ? "Shadowed by negated match" : "Shadowed rule",
            detail: `${later.id} is unreachable: ${earlier.id} matches a superset and terminates with ${terminal}.`,
            sample: chain.hook
              ? (synthesizePacket(later.match, chain.hook) ?? undefined)
              : undefined,
          });
        }
      }
    }

    // Partial shadow: the accept still wins for some packets, but an earlier
    // non-boilerplate deny steals an overlapping subset. A single missed sample
    // is not proof that a rule is dead.
    if (chain.hook) {
      for (const rule of chain.rules) {
        if (rule.action !== "accept") continue;
        if (
          findings.some(
            (finding) => finding.kind === "shadow" && finding.ruleId === rule.id,
          )
        ) {
          continue;
        }
        const reached = firstReachingPacket(policy, chain, rule);
        if (!reached) continue;

        for (const earlier of chain.rules) {
          if (earlier.id === rule.id) break;
          if (isBoilerplateGuard(earlier)) continue;
          const terminal = terminalAction(earlier, policy);
          if (terminal !== "drop" && terminal !== "reject") continue;
          const sample = intersectPacket(rule.match, earlier.match, chain.hook);
          if (!sample) continue;
          const result = probe(policy, sample);
          if (
            result.matchedRule?.id === earlier.id &&
            result.verdict !== rule.action
          ) {
            push({
              id: `${chain.name}:${rule.id}:partial:${earlier.id}`,
              severity: "warn",
              kind: "shadow",
              chain: chain.name,
              ruleId: rule.id,
              relatedRuleId: earlier.id,
              title: "Partially shadowed",
              detail: `${rule.id} still matches some packets, but ${earlier.id} ${terminal}s an overlapping subset first.`,
              sample,
            });
          }
        }
      }
    }

    if (chain.hook === "input" && chain.policy === "accept") {
      push({
        id: `${chain.name}:policy-accept`,
        severity: "info",
        kind: "smell",
        chain: chain.name,
        ruleId: "(policy)",
        title: "Permissive chain policy",
        detail: `${chain.name} defaults to accept — unknown ports are allowed.`,
      });
    }

    for (const rule of chain.rules) {
      if (rule.action === "jump") {
        const target = rule.jump?.trim();
        if (!target || !findChain(policy, target)) {
          push({
            id: `${chain.name}:${rule.id}:bad-jump`,
            severity: "error",
            kind: "smell",
            chain: chain.name,
            ruleId: rule.id,
            title: "Broken jump target",
            detail: target
              ? `${rule.id} jumps to missing chain "${target}".`
              : `${rule.id} is a jump without a target chain.`,
          });
        }
      }
    }
  }

  return findings;
}

export function runSuite(
  policy: Policy,
  cases: Array<{
    id: string;
    label: string;
    packet: Packet;
    expect: { verdict: Verdict; matchedRuleId: string | null };
  }>,
): Array<{
  id: string;
  label: string;
  ok: boolean;
  expected: { verdict: Verdict; matchedRuleId: string | null };
  actual: { verdict: Verdict; matchedRuleId: string | null };
  result: ProbeResult;
}> {
  return cases.map((c) => {
    const result = probe(policy, c.packet);
    const actual = {
      verdict: result.verdict,
      matchedRuleId: result.matchedRule?.id ?? null,
    };
    const ok =
      actual.verdict === c.expect.verdict &&
      actual.matchedRuleId === c.expect.matchedRuleId;
    return {
      id: c.id,
      label: c.label,
      ok,
      expected: c.expect,
      actual,
      result,
    };
  });
}

/** Exported for tests — confirms CIDR helpers reject garbage. */
export function assertIpv4OrThrow(ip: string): number {
  const n = ipToInt(ip);
  if (n === null) throw new Error(`invalid ipv4: ${ip}`);
  return n;
}
