import { describe, expect, it } from "vitest";
import {
  auditPolicy,
  formatCli,
  matchCovers,
  probe,
  runSuite,
  synthesizePacket,
} from "./evaluate";
import { cidrCovers, ipInCidr, ipToInt, parseCidr } from "./ip";
import { DEMO_POLICY, PRESETS, type Packet, type Policy } from "./policy";
import { validatePacket } from "./validate";

describe("ip helpers", () => {
  it("parses IPv4 and trims", () => {
    expect(ipToInt("10.0.0.1")).toBe((10 << 24) + 1);
    expect(ipToInt(" 10.0.0.1 ")).toBe((10 << 24) + 1);
    expect(ipToInt("256.0.0.1")).toBeNull();
    expect(ipToInt("1.2.3")).toBeNull();
  });

  it("matches CIDR and negation", () => {
    expect(ipInCidr("10.0.4.12", "10.0.4.0/24")).toBe(true);
    expect(ipInCidr("10.0.5.1", "10.0.4.0/24")).toBe(false);
    expect(ipInCidr("203.0.113.9", "!10.0.0.0/8")).toBe(true);
    expect(ipInCidr("10.1.1.1", "!10.0.0.0/8")).toBe(false);
    expect(parseCidr("10.0.0.0/33")).toBeNull();
  });

  it("covers positive and negated CIDRs", () => {
    expect(cidrCovers("10.0.0.0/8", "10.0.4.0/24")).toBe(true);
    expect(cidrCovers("10.0.4.0/24", "10.0.0.0/8")).toBe(false);
    expect(cidrCovers("!10.0.0.0/8", "203.0.113.0/24")).toBe(true);
    expect(cidrCovers("!10.0.0.0/8", "10.0.4.0/24")).toBe(false);
  });
});

describe("probe scenarios", () => {
  it("passes the full preset suite", () => {
    const results = runSuite(DEMO_POLICY, PRESETS);
    const failures = results.filter((r) => !r.ok);
    expect(
      failures.map((f) => ({
        id: f.id,
        expected: f.expected,
        actual: f.actual,
      })),
    ).toEqual([]);
  });

  it("walks jump into services for HTTP", () => {
    const preset = PRESETS.find((p) => p.id === "http-jump")!;
    const result = probe(DEMO_POLICY, preset.packet);
    expect(result.verdict).toBe("accept");
    expect(result.matchedRule?.id).toBe("svc-http");
    expect(result.path.some((s) => s.effect === "jump")).toBe(true);
    expect(result.depth).toBeGreaterThanOrEqual(1);
  });

  it("returns from user chain and continues", () => {
    const policy: Policy = {
      name: "ret",
      family: "inet",
      table: "filter",
      description: "return test",
      chains: [
        {
          name: "INPUT",
          hook: "input",
          policy: "drop",
          rules: [
            {
              id: "j",
              comment: "jump",
              match: { proto: "tcp", dport: 7 },
              action: "jump",
              jump: "tmp",
            },
            {
              id: "after",
              comment: "after return",
              match: { proto: "tcp", dport: 7 },
              action: "accept",
            },
          ],
        },
        {
          name: "tmp",
          policy: "drop",
          rules: [
            {
              id: "r",
              comment: "return",
              match: { any: true },
              action: "return",
            },
          ],
        },
      ],
    };
    const result = probe(policy, {
      src: "1.1.1.1",
      dst: "2.2.2.2",
      sport: 1,
      dport: 7,
      proto: "tcp",
      iif: "eth0",
      oif: "eth0",
      direction: "input",
      ctState: "new",
    });
    expect(result.verdict).toBe("accept");
    expect(result.matchedRule?.id).toBe("after");
    expect(result.path.some((s) => s.effect === "return")).toBe(true);
  });

  it("drops on missing jump target", () => {
    const policy: Policy = {
      name: "bad",
      family: "inet",
      table: "filter",
      description: "bad jump",
      chains: [
        {
          name: "INPUT",
          hook: "input",
          policy: "accept",
          rules: [
            {
              id: "j",
              comment: "broken",
              match: { any: true },
              action: "jump",
              jump: "nope",
            },
          ],
        },
      ],
    };
    const result = probe(policy, PRESETS[0]!.packet);
    expect(result.verdict).toBe("drop");
    expect(result.matchedRule?.id).toContain("missing");
  });

  it("falls through OUTPUT policy for HTTPS", () => {
    const preset = PRESETS.find((p) => p.id === "out-https-policy")!;
    const result = probe(DEMO_POLICY, preset.packet);
    expect(result.verdict).toBe("accept");
    expect(result.policyFallback).toBe(true);
    expect(result.matchedRule).toBeNull();
  });

  it("trims packet IPs while probing", () => {
    const preset = PRESETS.find((p) => p.id === "ssh-mgmt")!;
    const result = probe(DEMO_POLICY, {
      ...preset.packet,
      src: " 10.0.2.15 ",
      dst: " 10.0.1.10 ",
    });
    expect(result.verdict).toBe("accept");
    expect(result.matchedRule?.id).toBe("in-ssh");
  });

  it("formats a CLI invocation", () => {
    const preset = PRESETS.find((p) => p.id === "ssh-mgmt")!;
    const cli = formatCli(preset.packet);
    expect(cli).toContain("--src 10.0.2.15");
    expect(cli).toContain("--dport 22");
    expect(cli).toContain("--dir input");
  });
});

describe("audit", () => {
  it("fully shadows metrics and only partially shadows DNS", () => {
    const internal = PRESETS.find((p) => p.id === "dns-internal")!;
    const reached = probe(DEMO_POLICY, internal.packet);
    expect(reached.verdict).toBe("accept");
    expect(reached.matchedRule?.id).toBe("in-dns");

    const findings = auditPolicy(DEMO_POLICY);
    expect(
      findings.map((f) => ({
        rule: f.ruleId,
        severity: f.severity,
        title: f.title,
      })),
    ).toEqual([
      {
        rule: "in-metrics",
        severity: "error",
        title: "Shadowed by negated match",
      },
      {
        rule: "in-dns",
        severity: "warn",
        title: "Partially shadowed",
      },
    ]);

    const dns = findings.find((f) => f.ruleId === "in-dns");
    expect(dns?.sample).toBeTruthy();
    const stolen = probe(DEMO_POLICY, dns!.sample!);
    expect(stolen.verdict).toBe("drop");
    expect(stolen.matchedRule?.id).toBe("in-ext-drop");

    const metrics = findings.find((f) => f.ruleId === "in-metrics");
    expect(metrics?.sample).toBeTruthy();
    const buried = probe(DEMO_POLICY, metrics!.sample!);
    expect(buried.matchedRule?.id).toBe("in-ext-drop");
  });

  it("detects exact match coverage including negated CIDR", () => {
    expect(
      matchCovers(
        { proto: "tcp", dport: 443 },
        { proto: "tcp", dport: 443, saddrCidr: "10.0.0.0/8" },
      ),
    ).toBe(true);
    expect(
      matchCovers(
        { proto: "tcp", dport: 22 },
        { proto: "tcp", dport: 443 },
      ),
    ).toBe(false);
    expect(
      matchCovers(
        { saddrCidr: "!10.0.0.0/8" },
        { proto: "tcp", dport: 9100, saddrCidr: "203.0.113.0/24" },
      ),
    ).toBe(true);
  });

  it("synthesizes packets that satisfy matches", () => {
    const sample = synthesizePacket({
      proto: "tcp",
      dport: 22,
      saddrCidr: "10.0.0.0/8",
    });
    expect(sample?.dport).toBe(22);
    expect(sample?.src.startsWith("10.")).toBe(true);
  });
});

describe("validatePacket", () => {
  it("accepts a clean preset packet", () => {
    expect(validatePacket(PRESETS[0]!.packet)).toEqual([]);
  });

  it("accepts trimmed IPs", () => {
    expect(
      validatePacket({ ...PRESETS[0]!.packet, src: " 10.0.2.15 " }),
    ).toEqual([]);
  });

  it("rejects bad IPs and ports", () => {
    const errors = validatePacket({
      ...PRESETS[0]!.packet,
      src: "999.1.1.1",
      sport: 70000,
      iif: "",
    });
    expect(errors.map((e) => e.field).sort()).toEqual(["iif", "sport", "src"]);
  });

  it("does not hard-fail ICMP with non-zero ports", () => {
    const errors = validatePacket({
      ...PRESETS[0]!.packet,
      proto: "icmp",
      sport: 1,
      dport: 1,
    });
    expect(errors).toEqual([]);
  });

  it("rejects non-canonical IPv4 and non-integer ports", () => {
    const errors = validatePacket({
      ...PRESETS[0]!.packet,
      src: "01.2.3.4",
      dst: "1e1.0.0.1",
      sport: 22.5,
      dport: -1,
      oif: "   ",
    });
    expect(errors.map((e) => e.field).sort()).toEqual([
      "dport",
      "dst",
      "oif",
      "sport",
      "src",
    ]);
  });
});

function lab(chains: Policy["chains"], name = "lab"): Policy {
  return {
    name,
    family: "inet",
    table: "filter",
    description: name,
    chains,
  };
}

function pkt(over: Partial<Packet> = {}): Packet {
  return {
    src: "1.1.1.1",
    dst: "2.2.2.2",
    sport: 40000,
    dport: 80,
    proto: "tcp",
    iif: "eth0",
    oif: "eth0",
    direction: "input",
    ctState: "new",
    ...over,
  };
}

describe("engine edge cases", () => {
  it("follows the hook field when the chain is not named INPUT", () => {
    const result = probe(
      lab([
        {
          name: "ingress",
          hook: "input",
          policy: "accept",
          rules: [
            {
              id: "allow",
              comment: "all",
              match: { any: true },
              action: "accept",
            },
          ],
        },
      ]),
      pkt(),
    );
    expect(result.chain).toBe("ingress");
    expect(result.verdict).toBe("accept");
    expect(result.matchedRule?.id).toBe("allow");
  });

  it("drops when no base chain is hooked to the direction", () => {
    const result = probe(lab([]), pkt({ direction: "forward" }));
    expect(result.verdict).toBe("drop");
    expect(result.policyFallback).toBe(true);
    expect(result.matchedRule).toBeNull();
    expect(result.reason).toContain("forward");
  });

  it("treats falling off a user chain as return, not its policy", () => {
    const result = probe(
      lab([
        {
          name: "INPUT",
          hook: "input",
          policy: "drop",
          rules: [
            {
              id: "j",
              comment: "jump",
              match: { proto: "tcp", dport: 9 },
              action: "jump",
              jump: "empty",
            },
            {
              id: "after",
              comment: "after the jump",
              match: { proto: "tcp", dport: 9 },
              action: "accept",
            },
          ],
        },
        { name: "empty", policy: "drop", rules: [] },
      ]),
      pkt({ dport: 9 }),
    );
    expect(result.verdict).toBe("accept");
    expect(result.matchedRule?.id).toBe("after");
    expect(result.path.some((step) => step.effect === "jump")).toBe(true);
  });

  it("drops a jump cycle at depth 32", () => {
    const result = probe(
      lab([
        {
          name: "INPUT",
          hook: "input",
          policy: "accept",
          rules: [
            {
              id: "enter",
              comment: "enter",
              match: { any: true },
              action: "jump",
              jump: "loop",
            },
          ],
        },
        {
          name: "loop",
          policy: "drop",
          rules: [
            {
              id: "again",
              comment: "again",
              match: { any: true },
              action: "jump",
              jump: "loop",
            },
          ],
        },
      ]),
      pkt(),
    );
    expect(result.verdict).toBe("drop");
    expect(result.matchedRule?.id).toBe("engine:max-depth");
    expect(result.path.filter((step) => step.effect === "jump")).toHaveLength(32);
  });

  it("continues past a continue rule", () => {
    const result = probe(
      lab([
        {
          name: "INPUT",
          hook: "input",
          policy: "drop",
          rules: [
            {
              id: "note",
              comment: "count and continue",
              match: { any: true },
              action: "continue",
            },
            {
              id: "allow",
              comment: "allow",
              match: { proto: "tcp", dport: 9 },
              action: "accept",
            },
          ],
        },
      ]),
      pkt({ dport: 9 }),
    );
    expect(result.verdict).toBe("accept");
    expect(result.matchedRule?.id).toBe("allow");
    expect(result.path.some((step) => step.effect === "continue")).toBe(true);
    const findings = auditPolicy(
      lab([
        {
          name: "INPUT",
          hook: "input",
          policy: "drop",
          rules: [
            {
              id: "note",
              comment: "count and continue",
              match: { any: true },
              action: "continue",
            },
            {
              id: "allow",
              comment: "allow",
              match: { proto: "tcp", dport: 9 },
              action: "accept",
            },
          ],
        },
      ]),
    );
    expect(findings.some((f) => f.kind === "shadow")).toBe(false);
  });

  it("quotes shell metacharacters in the CLI export", () => {
    const cli = formatCli(pkt({ iif: "eth0;id", src: "10.0.0.1" }));
    expect(cli).toContain("--src 10.0.0.1");
    expect(cli).toContain("--iif 'eth0;id'");
    expect(cli).not.toContain("--iif eth0;id");
  });

  it("picks an address outside a negated CIDR", () => {
    const sample = synthesizePacket({ saddrCidr: "!203.0.113.0/24" });
    expect(sample).not.toBeNull();
    expect(ipInCidr(sample!.src, "!203.0.113.0/24")).toBe(true);
    expect(ipInCidr(sample!.src, "203.0.113.0/24")).toBe(false);
  });

  it("flags return, broken jumps, empty accepts, and bad matchers", () => {
    const findings = auditPolicy(
      lab([
        {
          name: "INPUT",
          hook: "input",
          policy: "accept",
          rules: [
            {
              id: "back",
              comment: "return all",
              match: { any: true },
              action: "return",
            },
            {
              id: "later",
              comment: "dead",
              match: { proto: "tcp", dport: 9 },
              action: "accept",
            },
          ],
        },
        {
          name: "FORWARD",
          hook: "forward",
          policy: "drop",
          rules: [
            {
              id: "wide",
              comment: "bare accept",
              match: {},
              action: "accept",
            },
            {
              id: "wide-dup",
              comment: "same",
              match: {},
              action: "drop",
            },
            {
              id: "bad-jump",
              comment: "missing",
              match: { proto: "udp", dport: 53 },
              action: "jump",
              jump: "nope",
            },
            {
              id: "after-bad-jump",
              comment: "dead",
              match: { proto: "udp", dport: 53, saddrCidr: "10.0.0.0/8" },
              action: "accept",
            },
            {
              id: "bad-cidr",
              comment: "garbage",
              match: { saddrCidr: "10.0.0.0/99" },
              action: "accept",
            },
            {
              id: "bad-port",
              comment: "port",
              match: { proto: "tcp", dport: 70000 },
              action: "drop",
            },
            {
              id: "empty-ct",
              comment: "ct",
              match: { ctState: [] },
              action: "drop",
            },
          ],
        },
        {
          name: "INPUT",
          hook: "input",
          policy: "drop",
          rules: [],
        },
      ]),
    );

    const titles = findings.map((f) => `${f.ruleId}:${f.title}`);
    expect(titles).toContain("later:Shadowed rule");
    expect(titles).toContain("wide:Accept-all before later rules");
    expect(titles).toContain("wide-dup:Duplicate match");
    expect(titles).toContain("after-bad-jump:Shadowed rule");
    expect(titles).toContain("bad-jump:Broken jump target");
    expect(titles).toContain("bad-cidr:Invalid source CIDR");
    expect(titles).toContain("bad-port:Port out of range");
    expect(titles).toContain("empty-ct:Empty conntrack match");
    expect(titles).toContain("(chain):Duplicate chain name");
    expect(titles).toContain("(hook):Duplicate hook");
    expect(titles).toContain("(policy):Permissive chain policy");
  });

  it("does not call a single missed sample an unreachable accept", () => {
    const policy = lab([
      {
        name: "INPUT",
        hook: "input",
        policy: "drop",
        rules: [
          {
            id: "drop-public",
            comment: "drop documentation range",
            match: { saddrCidr: "203.0.113.0/24" },
            action: "drop",
          },
          {
            id: "allow-rest",
            comment: "everyone else",
            match: { proto: "tcp", dport: 9 },
            action: "accept",
          },
        ],
      },
    ]);
    const findings = auditPolicy(policy);
    expect(findings.some((f) => f.title === "Accept rule not reachable")).toBe(
      false,
    );
    expect(findings.some((f) => f.ruleId === "allow-rest" && f.severity === "error")).toBe(
      false,
    );
    expect(
      findings.some(
        (f) => f.ruleId === "allow-rest" && f.title === "Partially shadowed",
      ),
    ).toBe(true);
    const live = probe(policy, pkt({ src: "10.1.1.1", dport: 9 }));
    expect(live.matchedRule?.id).toBe("allow-rest");
  });
});
