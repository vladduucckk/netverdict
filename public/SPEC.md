# NetVerdict — Product Specification

**Version:** 0.1.0-draft  
**Status:** Product specification (MVP-bound)  
**License intent:** Apache-2.0  
**Primary language:** Go (CLI/daemon) + TypeScript (TUI helpers / optional web UI)

---

## 1. One-liner

**NetVerdict** is a local-first OS firewall debugger: simulate any packet against your live policy, see the exact rule that allows or drops it, and catch shadowed or conflicting rules before they reach production.

---

## 2. Problem

Operating-system firewalls (nftables, iptables, firewalld, ufw, pf, Windows Firewall) are powerful but opaque.

Operators routinely face:

1. **Opaque verdicts** — A connection fails. Was it the host firewall, a container chain, a Docker bridge rule, or something else? `nft list ruleset` dumps thousands of lines with no answer.
2. **Silent shadowing** — An earlier rule matches everything; later “important” rules never fire. Nobody notices until an outage or audit.
3. **Unsafe change** — Editing production rules is guesswork. There is no first-class “what if I add this rule?” simulation with impact analysis.
4. **Fragmented tooling** — Each OS and frontend (ufw, firewalld, pfSense-style pf, Windows MMC) speaks a different dialect. Knowledge does not transfer; CI cannot lint policy the same way everywhere.
5. **No explainability** — Unlike compilers (`-explain`) or query planners (`EXPLAIN`), firewall stacks rarely show *why* a packet got ACCEPT / DROP / REJECT.

Existing tools list rules, wrap them in nicer syntax, or generate them. Almost none treat the firewall as a **debuggable decision engine**.

---

## 3. Genius insight

Treat the firewall like a compiler + debugger for packets:

| Software world | NetVerdict world |
|----------------|------------------|
| Source code | Firewall policy (live or file) |
| IR / AST | Portable Policy IR (PPIR) |
| Interpreter / VM | Packet evaluator |
| Stack trace | Rule path (table → chain → rule → verdict) |
| Dead code | Shadowed / unreachable rules |
| Diff / PR checks | Policy diff + CI lint |
| Debugger watch | Interactive packet probe |

The product is not “another firewall.” It is the **missing observability and safety layer on top of the OS firewall you already run**.

---

## 4. Goals and non-goals

### Goals

- Explain live firewall decisions for a concrete packet (5-tuple + interface + direction).
- Detect shadowed, duplicate, and contradictory rules.
- Diff proposed policy vs current and report blast radius (newly allowed / newly denied flows).
- Stay **local-first**: no mandatory cloud, no telemetry by default.
- Start deep on **Linux nftables**, then expand backends without changing the UX.
- Ship a CLI that fits SSH sessions and CI; optional TUI/web for exploration.

### Non-goals (v1)

- Replacing nftables / pf / Windows Firewall as the enforcement engine.
- Managing fleet-wide policy orchestration (that can be a later “enterprise” layer).
- Acting as an IDS/IPS or deep packet inspector.
- Auto-remediating production without an explicit apply step.
- Requiring a SaaS account.

---

## 5. Target users

| Persona | Need |
|---------|------|
| **Linux SRE / platform engineer** | Debug “why can’t this pod/host reach X?” under time pressure |
| **Security engineer** | Prove that a harden pass actually closed paths; find dead rules |
| **Homelab / power user** | Understand ufw/firewalld/nft interactions without reading man pages for hours |
| **CI / platform teams** | Lint firewall-as-code PRs: no shadows, no accidental public SSH |

---

## 6. Product pillars

1. **Probe** — Ask: “What happens to this packet?” Get a verdict + rule path.
2. **Explain** — Human-readable reason chain; machine-readable JSON for scripts.
3. **Audit** — Find shadows, conflicts, overly broad rules, unused counters (when available).
4. **Diff** — Preview a change before apply; show newly opened / closed paths.
5. **Apply safely** — Snapshot → apply → verify probes → automatic rollback on failure (opt-in).

---

## 7. User experience

### 7.1 CLI (primary interface)

```bash
# Explain a packet against the live ruleset
netverdict probe \
  --src 10.0.4.12 --dst 10.0.1.20 --dport 5432 --proto tcp --iif eth0

# Output (human)
VERDICT: DROP
path:
  inet filter INPUT
    rule #14  ip saddr != 10.0.0.0/8  drop   ← matched
reason: source 10.0.4.12 is outside 10.0.0.0/8; earlier accepts did not match

# Machine output
netverdict probe ... --json
```

```bash
# Find problems in the live policy
netverdict audit
# → shadowed rules, duplicates, accept-any before deny, etc.

# Diff a proposed nftables file against live
netverdict diff ./proposed.nft

# Simulate many flows from a YAML suite (CI)
netverdict test ./probes.yaml
```

### 7.2 Interactive demo / optional web UI

A browser surface for demos and local exploration:

- Packet builder (src/dst/port/proto/interface)
- Animated rule-path walk
- Verdict badge (ALLOW / DROP / REJECT)
- Side panel: matched rule, skipped rules, shadows nearby

CLI remains the source of truth; UI is a viewer over the same engine.

### 7.3 TUI (phase 2)

Fullscreen explorer for large rulesets: search, jump to chain, pin probes, compare snapshots.

---

## 8. Core architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Collectors │────▶│  PPIR        │────▶│  Evaluator      │
│  nft/ipt/pf │     │  (portable   │     │  probe / audit  │
│  windows    │     │   policy IR) │     │  diff / test    │
└─────────────┘     └──────────────┘     └────────┬────────┘
                                                  │
                     ┌──────────────┐             │
                     │  Presenters  │◀────────────┘
                     │  CLI/TUI/JSON│
                     │  Web (opt.)  │
                     └──────────────┘
```

### 8.1 Portable Policy IR (PPIR)

Normalized representation independent of backend:

- Tables / chains / hooks / priorities
- Rules as ordered matchers + actions
- Objects: sets, maps, meters (as data the evaluator can consult)
- Metadata: source backend, line refs, counters when present

PPIR is versioned JSON/protobuf suitable for snapshots and golden tests.

### 8.2 Collectors (backends)

| Backend | Priority | Notes |
|---------|----------|-------|
| Linux nftables | P0 (MVP) | Parse `nft -j list ruleset` + optional netlink |
| iptables-nft / legacy | P1 | Via nft compatibility or `iptables-save` |
| firewalld / ufw | P1 | As overlays that compile into nft/ipt — show both “intent” and effective rules |
| OpenBSD/FreeBSD pf | P2 | `pfctl -sr` / anchors |
| Windows Filtering Platform | P3 | WFP API; harder semantics |

### 8.3 Evaluator

Deterministic packet walker:

1. Determine hook/path from direction + family (INPUT/FORWARD/OUTPUT/…).
2. Walk chains in policy order; honor jumps/gotos/returns.
3. Evaluate matchers (IP, port, iface, ct state, etc. — MVP subset first).
4. Emit full **trace** (visited rules) + **verdict**.
5. Support “counterfactual” mode: evaluate against a PPIR snapshot (file), not only live.

### 8.4 Audit engine

Static analysis over PPIR:

- **Shadow detection** — rule N is unreachable because rule M always matches a superset.
- **Contradiction** — overlapping matches with opposite actions in ambiguous orders.
- **Broad accepts** — `ip/any accept` before later denies.
- **Dead sets** — referenced empty sets (warn).
- **Policy smells** — raw Docker/iptables residue, duplicate drops, etc.

### 8.5 Diff & blast radius

Given A (current) and B (proposed):

- Structural rule diff
- Optional flow corpus (user-provided or generated samples) → verdict changes
- Report: newly allowed, newly denied, unchanged

---

## 9. MVP scope (v0.1)

Ship a **complete, usable slice**:

1. **Linux nftables collector** (JSON dump → PPIR).
2. **Probe** for IPv4 TCP/UDP/ICMP with src/dst/port/iface against INPUT/FORWARD/OUTPUT.
3. **Human + JSON** output with rule path.
4. **Audit**: basic shadow detection within a single chain.
5. **Demo ruleset** + interactive web simulator (no root required) for docs and onboarding.
6. **`netverdict test`** running a YAML probe suite against a fixture ruleset (CI-friendly).

Out of MVP: apply/rollback, pf/Windows, full conntrack emulation, GUI TUI.

---

## 10. Success metrics

| Metric | Target intuition |
|--------|------------------|
| Time-to-answer | “Why is this port closed?” answered in < 30s for a trained user |
| Trust | Probe verdict matches real connectivity in ≥ 95% of supported matcher cases (fixture suite) |
| Adoption signal | Stars + “replaced my nft list + guess loop” testimonials |
| CI value | Fail PRs that introduce shadowed rules or change critical probe verdicts |

---

## 11. Security & trust model

- Runs locally; root/CAP_NET_ADMIN only when reading live policy or applying changes.
- Fixture/demo mode never needs privileges.
- No network exfiltration by default; optional anonymous version check behind a flag.
- Clear warnings when the evaluator’s matcher coverage is incomplete for a ruleset feature (so users never get a false “ALLOW” from an unimplemented match).
- Supply-chain: reproducible builds, signed releases, SBOM.

---

## 12. Competitive landscape (positioning)

| Tool | What it does | Gap NetVerdict fills |
|------|--------------|----------------------|
| `nft` / `iptables` | Manage rules | No simulation/explain UX |
| ufw / firewalld | Simplify policy | Still opaque when something breaks underneath |
| Shorewall / Ansible firewall roles | Generate rules | Generation ≠ debugging live decisions |
| Cloud security groups consoles | Cloud only | Not for host OS / hybrid edge |
| Commercial NGFW consoles | Appliance-centric | Not local OSS for commodity Linux |

**Positioning line:** *Wireshark shows packets. NetVerdict shows why the firewall decided their fate.*

---

## 13. Roadmap (high level)

| Phase | Deliverable |
|-------|-------------|
| **0.1 MVP** | nftables probe + shadow audit + fixture tests + web demo |
| **0.2** | Diff + YAML probe suites as CI action |
| **0.3** | Safe apply with snapshot/rollback; firewalld/ufw overlays |
| **1.0** | Stable PPIR, solid matcher coverage, packaged distro installs |
| **1.x** | pf backend, TUI explorer |
| **2.x** | Windows WFP; optional multi-host policy compare |

---

## 14. Open source strategy

- **Apache-2.0** for broad corporate adoption.
- Good first issues: matcher implementations, fixture rulesets, docs translations.
- Design docs in-repo; RFCs for PPIR changes.
- Refuse to become a closed “policy cloud” — cloud features, if any, stay optional and separable.

---

## 15. Repository layout (intended)

```
/
├── SPEC.md                 # this document
├── README.md
├── cmd/netverdict/         # Go CLI (future / next commits)
├── internal/
│   ├── ppir/               # IR types + validation
│   ├── collect/nft/        # nftables collector
│   ├── eval/               # packet evaluator
│   └── audit/              # shadow/conflict analysis
├── fixtures/               # sample rulesets + probe suites
├── web/                    # interactive demo (this MVP surface)
└── docs/
```

For the initial repository seed, the **web demo + specification** ship first so the product idea is tangible; the Go engine follows as the enforcement-backed CLI.

---

## 16. Demo acceptance criteria (web seed)

- User can set src, dst, dport, proto and run a probe against a built-in sample nftables-like policy.
- UI shows verdict, ordered rule path, and which rule matched.
- At least one scenario demonstrates a **shadowed rule** discovery.
- Works on desktop and mobile viewports.
- No backend required for the demo (pure client evaluation of the fixture).

---

## 17. Naming

| Field | Value |
|-------|-------|
| **Product name** | NetVerdict |
| **Repository name** | `netverdict` |
| **Short description** | Local-first OS firewall debugger — simulate packets, explain verdicts, catch shadowed rules. |
| **CLI binary** | `netverdict` |
| **Tagline** | Know why the firewall said no. |

---

## 18. Risks

| Risk | Mitigation |
|------|------------|
| Incomplete matcher parity → wrong verdicts | Explicit “unsupported match” failures; never silent ignore in strict mode |
| nftables JSON quirks across versions | Fixture matrix on multiple kernel/nft versions in CI |
| Users expect apply magic day one | MVP messaging focuses on probe/audit; apply is phase 0.3 |
| Scope creep into full NGFW | Keep charter: debug & verify existing OS firewalls |

---

## 19. Summary

NetVerdict turns the OS firewall from a black box into a **debuggable policy engine**. The genius is not a new rule language — it is **explainability, simulation, and conflict detection** on the firewall you already have, local-first and CI-ready.
