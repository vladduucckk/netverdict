"use client";

import { useMemo, useRef, useState } from "react";
import {
  auditPolicy,
  formatCli,
  probe,
  ruleExpression,
  runSuite,
  type AuditFinding,
  type ProbeResult,
} from "@/lib/evaluate";
import {
  DEMO_POLICY,
  PRESETS,
  type Direction,
  type Packet,
  type Preset,
  type Proto,
  type CtState,
} from "@/lib/policy";
import { validatePacket } from "@/lib/validate";

type Tab = "probe" | "policy" | "audit" | "suite";

const GROUPS: Array<{ id: Preset["group"]; label: string }> = [
  { id: "input", label: "INPUT" },
  { id: "forward", label: "FORWARD" },
  { id: "output", label: "OUTPUT" },
  { id: "shadow", label: "Shadow bugs" },
];

function VerdictPill({
  verdict,
  pulse,
}: {
  verdict: ProbeResult["verdict"];
  pulse?: boolean;
}) {
  const map: Record<string, { bg: string; fg: string }> = {
    accept: { bg: "var(--allow-soft)", fg: "var(--allow)" },
    drop: { bg: "var(--drop-soft)", fg: "var(--drop)" },
    reject: { bg: "var(--reject-soft)", fg: "var(--reject)" },
    continue: { bg: "var(--paper)", fg: "var(--mute)" },
  };
  const s = map[verdict] ?? map.continue!;
  return (
    <span
      data-testid="verdict-pill"
      className={`inline-flex items-center px-2.5 py-1 font-mono text-xs font-semibold uppercase tracking-[0.14em] ${pulse ? "anim-flash" : ""}`}
      style={{ background: s.bg, color: s.fg }}
    >
      {verdict}
    </span>
  );
}

function SeverityDot({ severity }: { severity: AuditFinding["severity"] }) {
  const color =
    severity === "error"
      ? "var(--drop)"
      : severity === "warn"
        ? "var(--warn)"
        : "var(--mute)";
  return (
    <span
      className="mt-1.5 inline-block h-2 w-2 shrink-0 rounded-full"
      style={{ background: color }}
      aria-hidden
    />
  );
}

function samePacket(a: Packet, b: Packet): boolean {
  return (
    a.src === b.src &&
    a.dst === b.dst &&
    a.sport === b.sport &&
    a.dport === b.dport &&
    a.proto === b.proto &&
    a.iif === b.iif &&
    a.oif === b.oif &&
    a.direction === b.direction &&
    a.ctState === b.ctState
  );
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function Workspace() {
  const [tab, setTab] = useState<Tab>("probe");
  const [presetId, setPresetId] = useState(PRESETS[0]!.id);
  const [packet, setPacket] = useState<Packet>({ ...PRESETS[0]!.packet });
  const [animToken, setAnimToken] = useState(0);
  const [copied, setCopied] = useState<"cli" | "json" | "fail" | null>(null);
  const [suiteEpoch, setSuiteEpoch] = useState(0);
  const [suiteRanAt, setSuiteRanAt] = useState<string | null>(null);
  const [suiteFilter, setSuiteFilter] = useState<"all" | "fail">("all");
  const copyTimer = useRef<number | null>(null);

  const errors = useMemo(() => validatePacket(packet), [packet]);
  const errorByField = useMemo(() => {
    const map = new Map<string, string>();
    for (const e of errors) map.set(e.field, e.message);
    return map;
  }, [errors]);

  const result = useMemo(() => {
    if (errors.length > 0) return null;
    return probe(DEMO_POLICY, packet);
  }, [packet, errors]);

  const findings = useMemo(() => auditPolicy(DEMO_POLICY), []);
  const suite = useMemo(() => {
    void suiteEpoch;
    return runSuite(DEMO_POLICY, PRESETS);
  }, [suiteEpoch]);
  const suitePass = suite.filter((s) => s.ok).length;
  const packetKey = useMemo(() => JSON.stringify(packet), [packet]);

  function loadPreset(preset: Preset) {
    setPresetId(preset.id);
    setPacket({ ...preset.packet });
    setAnimToken((n) => n + 1);
    setTab("probe");
  }

  function openPacket(next: Packet) {
    const preset = PRESETS.find((item) => samePacket(item.packet, next));
    if (preset) {
      loadPreset(preset);
      return;
    }
    setPresetId("");
    setPacket({ ...next });
    setAnimToken((n) => n + 1);
    setTab("probe");
  }

  function update<K extends keyof Packet>(key: K, value: Packet[K]) {
    setPresetId("");
    setPacket((prev) => {
      const next = { ...prev, [key]: value };
      // ICMP uses port 0 by convention — avoid trapping the user in validation limbo
      if (key === "proto" && value === "icmp") {
        next.sport = 0;
        next.dport = 0;
      }
      return next;
    });
  }

  function replayProbe() {
    setAnimToken((n) => n + 1);
  }

  function runSuiteNow() {
    setSuiteEpoch((n) => n + 1);
    setSuiteFilter("all");
    setSuiteRanAt(
      new Date().toLocaleTimeString("en-GB", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
    );
  }

  async function onCopy(kind: "cli" | "json") {
    if (!result) return;
    const text =
      kind === "cli"
        ? formatCli(packet)
        : JSON.stringify(
            {
              packet,
              verdict: result.verdict,
              matchedRule: result.matchedRule?.id ?? null,
              matchedChain: result.matchedChain,
              policyFallback: result.policyFallback,
              path: result.path.map((s) => ({
                chain: s.chain,
                rule: s.rule.id,
                matched: s.matched,
                effect: s.effect ?? null,
                skip: s.skippedReason ?? null,
              })),
            },
            null,
            2,
          );
    const ok = await copyText(text);
    setCopied(ok ? kind : "fail");
    if (copyTimer.current !== null) window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setCopied(null), 1600);
  }

  const activePreset = PRESETS.find((p) => p.id === presetId);

  return (
    <div id="root-shell" className="mx-auto flex min-h-full w-full max-w-[1280px] flex-col px-4 pb-16 pt-5 sm:px-6 lg:px-8">
      <header className="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--line)] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <span className="anim-dot inline-block h-2.5 w-2.5 rounded-full bg-[var(--accent)]" />
            <p className="font-display text-3xl font-bold tracking-tight text-[var(--ink)] sm:text-4xl">
              NetVerdict
            </p>
          </div>
          <p className="mt-2 max-w-xl text-sm text-[var(--mute)] sm:text-base">
            Probe a packet against sample host policy. See the exact rule path,
            audit shadows, run the full scenario suite.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--mute)]">
          <span className="font-mono text-[var(--ink-2)]">
            {DEMO_POLICY.family}/{DEMO_POLICY.table}
          </span>
          <span aria-hidden>·</span>
          <span className="font-mono">{DEMO_POLICY.name}</span>
          <span aria-hidden>·</span>
          <span>{PRESETS.length} scenarios</span>
        </div>
      </header>

      <nav
        className="mt-4 flex gap-5 overflow-x-auto border-b border-[var(--line)]"
        aria-label="Workspace"
      >
        {(
          [
            ["probe", "Probe"],
            ["policy", "Policy"],
            ["audit", `Audit (${findings.length})`],
            ["suite", `Suite (${suitePass}/${suite.length})`],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            className="tab shrink-0"
            data-active={tab === id}
            onClick={() => {
              setTab(id);
              if (id === "suite" && suiteRanAt === null) runSuiteNow();
            }}
          >
            {label}
          </button>
        ))}
      </nav>

      <main className="mt-6 flex-1">
        {tab === "probe" && (
          <div className="grid gap-6 lg:grid-cols-[minmax(0,0.95fr)_minmax(0,1.15fr)]">
            <section className="space-y-5">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--mute)]">
                  Scenarios
                </p>
                <div className="mt-3 space-y-3">
                  {GROUPS.map((group) => (
                    <div key={group.id}>
                      <p className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--mute)]">
                        {group.label}
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {PRESETS.filter((p) => p.group === group.id).map((preset) => {
                          const active = preset.id === presetId;
                          return (
                            <button
                              key={preset.id}
                              type="button"
                              onClick={() => loadPreset(preset)}
                              className={`border px-2.5 py-1.5 text-left text-xs transition ${
                                active
                                  ? "border-[var(--ink)] bg-[var(--ink)] text-[var(--accent)]"
                                  : "border-[var(--line)] bg-[var(--panel)] text-[var(--ink-2)] hover:border-[var(--line-strong)]"
                              }`}
                            >
                              {preset.label}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <form
                className="panel p-4"
                onSubmit={(e) => {
                  e.preventDefault();
                  replayProbe();
                }}
              >
                <div className="mb-3 flex items-center justify-between gap-3">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--mute)]">
                    Packet
                  </p>
                  {activePreset ? (
                    <span className="font-mono text-[10px] text-[var(--mute)]">
                      expect {activePreset.expect.verdict}
                      {activePreset.expect.matchedRuleId
                        ? ` @ ${activePreset.expect.matchedRuleId}`
                        : " @ policy"}
                    </span>
                  ) : (
                    <span className="font-mono text-[10px] text-[var(--mute)]">
                      custom
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3">
                  {(
                    [
                      ["src", "src", packet.src],
                      ["dst", "dst", packet.dst],
                      ["iif", "iif", packet.iif],
                      ["oif", "oif", packet.oif],
                    ] as const
                  ).map(([key, label, value]) => (
                    <label key={key} className="block">
                      <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--mute)]">
                        {label}
                      </span>
                      <input
                        className="field"
                        value={value}
                        aria-invalid={errorByField.has(key)}
                        onChange={(e) => update(key, e.target.value)}
                      />
                    </label>
                  ))}
                  <label className="block">
                    <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--mute)]">
                      sport
                    </span>
                    <input
                      className="field"
                      type="number"
                      min={0}
                      max={65535}
                      value={packet.sport}
                      aria-invalid={errorByField.has("sport")}
                      onChange={(e) => update("sport", Number(e.target.value))}
                    />
                  </label>
                  <label className="block">
                    <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--mute)]">
                      dport
                    </span>
                    <input
                      className="field"
                      type="number"
                      min={0}
                      max={65535}
                      value={packet.dport}
                      aria-invalid={errorByField.has("dport")}
                      onChange={(e) => update("dport", Number(e.target.value))}
                    />
                  </label>
                  <label className="block">
                    <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--mute)]">
                      proto
                    </span>
                    <select
                      className="field"
                      value={packet.proto}
                      onChange={(e) => update("proto", e.target.value as Proto)}
                    >
                      <option value="tcp">tcp</option>
                      <option value="udp">udp</option>
                      <option value="icmp">icmp</option>
                    </select>
                  </label>
                  <label className="block">
                    <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--mute)]">
                      direction
                    </span>
                    <select
                      className="field"
                      value={packet.direction}
                      onChange={(e) =>
                        update("direction", e.target.value as Direction)
                      }
                    >
                      <option value="input">input</option>
                      <option value="forward">forward</option>
                      <option value="output">output</option>
                    </select>
                  </label>
                  <label className="block">
                    <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--mute)]">
                      ct state
                    </span>
                    <select
                      className="field"
                      value={packet.ctState}
                      onChange={(e) =>
                        update("ctState", e.target.value as CtState)
                      }
                    >
                      <option value="new">new</option>
                      <option value="established">established</option>
                      <option value="related">related</option>
                      <option value="invalid">invalid</option>
                    </select>
                  </label>
                </div>

                {errors.length > 0 && (
                  <ul className="mt-3 space-y-1 text-xs text-[var(--drop)]" role="alert">
                    {errors.map((e) => (
                      <li key={`${e.field}-${e.message}`}>{e.message}</li>
                    ))}
                  </ul>
                )}

                <div className="mt-4 flex flex-wrap gap-2">
                  <button type="submit" className="btn btn-accent">
                    Probe packet
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => onCopy("cli")}
                    disabled={!result}
                  >
                    {copied === "cli" ? "Copied CLI" : "Copy CLI"}
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => onCopy("json")}
                    disabled={!result}
                  >
                    {copied === "json" ? "Copied JSON" : "Copy JSON"}
                  </button>
                  {copied === "fail" && (
                    <span className="text-xs text-[var(--drop)]">
                      Clipboard unavailable
                    </span>
                  )}
                </div>
              </form>
            </section>

            <section className="space-y-4">
              {result ? (
                <div key={`${packetKey}-${animToken}`} className="panel anim-rise p-4 sm:p-5">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--mute)]">
                        Verdict · {result.table}/{result.chain}
                        {result.matchedChain && result.matchedChain !== result.chain
                          ? ` → ${result.matchedChain}`
                          : ""}
                      </p>
                      <p className="mt-2 max-w-xl text-base text-[var(--ink)] sm:text-lg">
                        {result.reason}
                      </p>
                      {result.policyFallback && (
                        <p className="mt-1 text-xs text-[var(--mute)]">
                          No rule matched — chain policy applied.
                        </p>
                      )}
                    </div>
                    <VerdictPill verdict={result.verdict} pulse />
                  </div>

                  <ol className="scroll-thin mt-5 max-h-[28rem] space-y-1.5 overflow-y-auto pr-1">
                    {result.path.map((step, index) => {
                      return (
                        <li
                          key={`${step.chain}-${step.rule.id}-${index}`}
                          className={`anim-row flex gap-3 border px-3 py-2 font-mono text-[11px] sm:text-xs ${
                            step.matched
                              ? "border-[var(--ink)] bg-[var(--accent)]/25"
                              : "border-[var(--line)] bg-[var(--paper-2)]"
                          }`}
                          style={{ animationDelay: `${index * 40}ms` }}
                        >
                          <span className="w-6 shrink-0 text-[var(--mute)]">
                            {String(index + 1).padStart(2, "0")}
                          </span>
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-[var(--mute)]">{step.chain}</span>
                              <span className="font-semibold text-[var(--ink)]">
                                {step.rule.id}
                              </span>
                              {step.matched ? (
                                <span className="uppercase tracking-wider text-[var(--allow)]">
                                  {step.effect ?? "match"}
                                  {step.jumpTo ? ` → ${step.jumpTo}` : ""}
                                </span>
                              ) : (
                                <span className="text-[var(--mute)]">skip</span>
                              )}
                            </div>
                            <p className="mt-0.5 truncate text-[var(--ink-2)]">
                              {ruleExpression(step.rule)}
                            </p>
                            <p className="mt-0.5 text-[var(--mute)]">
                              {step.rule.comment}
                              {!step.matched && step.skippedReason
                                ? ` · ${step.skippedReason}`
                                : ""}
                            </p>
                          </div>
                        </li>
                      );
                    })}
                  </ol>
                </div>
              ) : (
                <div className="panel p-5 text-sm text-[var(--drop)]">
                  Fix packet fields to run a probe.
                </div>
              )}

              <div className="border border-dashed border-[var(--line-strong)] bg-[var(--panel)]/70 p-4 text-sm text-[var(--mute)]">
                <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--ink-2)]">
                  Policy note
                </p>
                <p className="mt-2 leading-relaxed">{DEMO_POLICY.description}</p>
              </div>
            </section>
          </div>
        )}

        {tab === "policy" && (
          <div className="space-y-4">
            <p className="max-w-2xl text-sm text-[var(--mute)]">
              Effective fixture ruleset used by the evaluator. Jump targets are
              first-class chains.
            </p>
            {DEMO_POLICY.chains.map((chain) => (
              <details
                key={chain.name}
                open={Boolean(chain.hook)}
                className="panel group"
              >
                <summary className="cursor-pointer list-none px-4 py-3 marker:content-none">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-3">
                      <span className="font-display text-lg font-semibold">
                        {chain.name}
                      </span>
                      {chain.hook && (
                        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--mute)]">
                          hook {chain.hook}
                        </span>
                      )}
                    </div>
                    <span className="font-mono text-xs text-[var(--mute)]" data-testid={`chain-meta-${chain.name}`}>
                      {chain.hook
                        ? `policy ${chain.policy} · ${chain.rules.length} rules`
                        : `implicit return · ${chain.rules.length} rules`}
                    </span>
                  </div>
                </summary>
                <div className="border-t border-[var(--line)] px-2 py-2 sm:px-3">
                  <ol className="space-y-1">
                    {chain.rules.map((rule, idx) => (
                      <li
                        key={rule.id}
                        className="grid grid-cols-[2rem_minmax(0,1fr)] gap-2 px-2 py-2 font-mono text-[11px] sm:text-xs hover:bg-[var(--paper-2)]"
                      >
                        <span className="text-[var(--mute)]">
                          {String(idx + 1).padStart(2, "0")}
                        </span>
                        <div className="min-w-0">
                          <div className="flex flex-wrap gap-2">
                            <span className="font-semibold">{rule.id}</span>
                            <span className="text-[var(--mute)]">{rule.comment}</span>
                          </div>
                          <p className="mt-0.5 truncate text-[var(--ink-2)]">
                            {ruleExpression(rule)}
                          </p>
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>
              </details>
            ))}
          </div>
        )}

        {tab === "audit" && (
          <div className="space-y-3">
            <p className="max-w-2xl text-sm text-[var(--mute)]">
              Static analysis over the fixture. Shadows with negated CIDRs are
              called out explicitly; identical and covering matches are detected
              automatically.
            </p>
            {findings.length === 0 ? (
              <p className="panel p-4 text-sm">No findings.</p>
            ) : (
              findings.map((f) => (
                <article
                  key={f.id}
                  className="panel flex gap-3 p-4"
                  data-testid="audit-finding"
                  data-rule={f.ruleId}
                  data-kind={f.kind}
                  data-severity={f.severity}
                >
                  <SeverityDot severity={f.severity} />
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="font-semibold text-[var(--ink)]">{f.title}</h3>
                      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-[var(--mute)]">
                        {f.kind} · {f.severity}
                      </span>
                    </div>
                    <p className="mt-1 text-sm text-[var(--ink-2)]">{f.detail}</p>
                    <p className="mt-2 font-mono text-xs text-[var(--mute)]">
                      {f.chain}/{f.ruleId}
                      {f.relatedRuleId ? ` ← ${f.relatedRuleId}` : ""}
                    </p>
                    {f.kind === "shadow" && f.sample && (
                      <button
                        type="button"
                        className="btn btn-secondary mt-3"
                        onClick={() => openPacket(f.sample!)}
                      >
                        Probe shadowed path
                      </button>
                    )}
                  </div>
                </article>
              ))
            )}
          </div>
        )}

        {tab === "suite" && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="max-w-2xl text-sm text-[var(--mute)]">
                Every preset has an expected verdict and matched rule id. Green
                means the evaluator agrees.
              </p>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="btn btn-accent"
                  onClick={runSuiteNow}
                >
                  Run all ({suite.length})
                </button>
                <button
                  type="button"
                  className={`btn ${suiteFilter === "all" ? "btn-primary" : "btn-secondary"}`}
                  onClick={() => setSuiteFilter("all")}
                >
                  Show all
                </button>
                <button
                  type="button"
                  className={`btn ${suiteFilter === "fail" ? "btn-primary" : "btn-secondary"}`}
                  onClick={() => setSuiteFilter("fail")}
                >
                  Failures only
                </button>
              </div>
            </div>

            <div className="panel flex flex-wrap items-center gap-4 px-4 py-3 text-sm">
              <span className="font-mono text-[var(--allow)]">
                {suitePass} passed
              </span>
              <span className="font-mono text-[var(--drop)]">
                {suite.length - suitePass} failed
              </span>
              <span className="text-[var(--mute)]">
                {suiteRanAt
                  ? `Last run ${suiteRanAt} · epoch ${suiteEpoch}`
                  : "Open this tab or click Run all"}
              </span>
            </div>

            <ul className="space-y-2">
              {suite.filter((row) => (suiteFilter === "fail" ? !row.ok : true))
                .length === 0 && (
                <li className="panel px-4 py-5 text-sm text-[var(--allow)]">
                  No failures — all {suite.length} scenarios passed.
                </li>
              )}
              {suite
                .filter((row) => (suiteFilter === "fail" ? !row.ok : true))
                .map((row, index) => (
                  <li
                    key={row.id}
                    data-testid="suite-row"
                    data-case={row.id}
                    data-ok={row.ok ? "true" : "false"}
                    className="panel flex flex-wrap items-center justify-between gap-3 px-4 py-3 anim-rise"
                    style={{ animationDelay: `${index * 20}ms` }}
                  >
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className="font-mono text-xs font-semibold uppercase tracking-[0.12em]"
                          style={{
                            color: row.ok ? "var(--allow)" : "var(--drop)",
                          }}
                        >
                          {row.ok ? "pass" : "fail"}
                        </span>
                        <span className="font-semibold">{row.label}</span>
                        <span className="font-mono text-[10px] text-[var(--mute)]">
                          {row.id}
                        </span>
                      </div>
                      <p className="mt-1 font-mono text-[11px] text-[var(--mute)]">
                        expect {row.expected.verdict}/
                        {row.expected.matchedRuleId ?? "policy"} · got{" "}
                        {row.actual.verdict}/{row.actual.matchedRuleId ?? "policy"}
                      </p>
                    </div>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => {
                        const preset = PRESETS.find((p) => p.id === row.id);
                        if (preset) loadPreset(preset);
                      }}
                    >
                      Open in probe
                    </button>
                  </li>
                ))}
            </ul>
          </div>
        )}
      </main>

      <footer className="mt-10 border-t border-[var(--line)] pt-4 text-xs text-[var(--mute)]">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="font-display font-semibold text-[var(--ink)]">
            NetVerdict
          </span>
          <span>
            Sample policy evaluator · not live nftables · see /SPEC.md
          </span>
        </div>
      </footer>
    </div>
  );
}
