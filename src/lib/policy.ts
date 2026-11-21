/** Sample nftables-like policy fixture for the interactive demo. */

export type Proto = "tcp" | "udp" | "icmp";
export type CtState = "new" | "established" | "related" | "invalid";
export type Direction = "input" | "forward" | "output";
export type Verdict = "accept" | "drop" | "reject" | "continue";
export type Action = Verdict | "jump" | "return";

export type Match = {
  iif?: string;
  oif?: string;
  proto?: Proto;
  sport?: number;
  dport?: number;
  saddrCidr?: string;
  daddrCidr?: string;
  ctState?: CtState[];
  /** When true, rule matches everything. */
  any?: boolean;
};

export type Rule = {
  id: string;
  comment: string;
  match: Match;
  action: Action;
  jump?: string;
};

export type Chain = {
  name: string;
  hook?: Direction;
  policy: "accept" | "drop";
  rules: Rule[];
};

export type Policy = {
  name: string;
  family: "inet";
  table: string;
  description: string;
  chains: Chain[];
};

export type Packet = {
  src: string;
  dst: string;
  sport: number;
  dport: number;
  proto: Proto;
  iif: string;
  oif: string;
  direction: Direction;
  ctState: CtState;
};

export const DEMO_POLICY: Policy = {
  name: "edge-lab",
  family: "inet",
  table: "filter",
  description:
    "Edge host with a deliberate ordering bug: a broad external drop fully shadows the metrics allow, and drops external DNS before the DNS allow. Management sources can still reach DNS.",
  chains: [
    {
      name: "INPUT",
      hook: "input",
      policy: "drop",
      rules: [
        {
          id: "in-est",
          comment: "allow established / related",
          match: { ctState: ["established", "related"] },
          action: "accept",
        },
        {
          id: "in-lo",
          comment: "loopback",
          match: { iif: "lo" },
          action: "accept",
        },
        {
          id: "in-invalid",
          comment: "drop invalid conntrack",
          match: { ctState: ["invalid"] },
          action: "drop",
        },
        {
          id: "in-ssh",
          comment: "SSH from management net",
          match: { proto: "tcp", dport: 22, saddrCidr: "10.0.0.0/8" },
          action: "accept",
        },
        {
          id: "in-https",
          comment: "HTTPS from anywhere",
          match: { proto: "tcp", dport: 443 },
          action: "accept",
        },
        {
          id: "in-http-redir",
          comment: "HTTP → services chain",
          match: { proto: "tcp", dport: 80 },
          action: "jump",
          jump: "services",
        },
        {
          id: "in-smb",
          comment: "drop scanners on 445",
          match: { proto: "tcp", dport: 445 },
          action: "drop",
        },
        {
          id: "in-pg",
          comment: "Postgres from app subnet",
          match: { proto: "tcp", dport: 5432, saddrCidr: "10.0.4.0/24" },
          action: "accept",
        },
        {
          id: "in-ext-drop",
          comment: "broad drop of non-10.0.0.0/8 sources (too early)",
          match: { saddrCidr: "!10.0.0.0/8" },
          action: "drop",
        },
        {
          id: "in-metrics",
          comment: "metrics scrape from CI (fully shadowed by in-ext-drop)",
          match: { proto: "tcp", dport: 9100, saddrCidr: "203.0.113.0/24" },
          action: "accept",
        },
        {
          id: "in-dns",
          comment: "DNS to resolver — external sources hit in-ext-drop first; 10/8 still matches",
          match: { proto: "udp", dport: 53, daddrCidr: "10.0.1.53/32" },
          action: "accept",
        },
        {
          id: "in-icmp",
          comment: "ping from management",
          match: { proto: "icmp", saddrCidr: "10.0.0.0/8" },
          action: "accept",
        },
      ],
    },
    {
      name: "services",
      // User chains have no hook policy in nftables; evaluator treats exhaustion as return.
      policy: "drop",
      rules: [
        {
          id: "svc-http",
          comment: "plain HTTP landing",
          match: { proto: "tcp", dport: 80 },
          action: "accept",
        },
        {
          id: "svc-default",
          comment: "no other service ports here",
          match: { any: true },
          action: "return",
        },
      ],
    },
    {
      name: "FORWARD",
      hook: "forward",
      policy: "drop",
      rules: [
        {
          id: "fw-est",
          comment: "allow established",
          match: { ctState: ["established", "related"] },
          action: "accept",
        },
        {
          id: "fw-app-db",
          comment: "app → db",
          match: {
            proto: "tcp",
            dport: 5432,
            saddrCidr: "10.0.4.0/24",
            daddrCidr: "10.0.1.20/32",
          },
          action: "accept",
        },
        {
          id: "fw-deny-db-world",
          comment: "explicit deny other DB paths",
          match: { proto: "tcp", dport: 5432 },
          action: "drop",
        },
      ],
    },
    {
      name: "OUTPUT",
      hook: "output",
      policy: "accept",
      rules: [
        {
          id: "out-smtp",
          comment: "block outbound SMTP (relay abuse)",
          match: { proto: "tcp", dport: 25 },
          action: "reject",
        },
        {
          id: "out-dns",
          comment: "allow DNS out eth0",
          match: { proto: "udp", dport: 53, oif: "eth0" },
          action: "accept",
        },
      ],
    },
  ],
};

export type Preset = {
  id: string;
  label: string;
  group: "input" | "forward" | "output" | "shadow";
  packet: Packet;
  expect: {
    verdict: Verdict;
    matchedRuleId: string | null;
  };
};

const base = {
  sport: 40000,
  iif: "eth0",
  oif: "eth0",
  ctState: "new" as CtState,
};

export const PRESETS: Preset[] = [
  {
    id: "ssh-mgmt",
    label: "SSH from mgmt",
    group: "input",
    packet: {
      ...base,
      src: "10.0.2.15",
      dst: "10.0.1.10",
      sport: 51234,
      dport: 22,
      proto: "tcp",
      direction: "input",
    },
    expect: { verdict: "accept", matchedRuleId: "in-ssh" },
  },
  {
    id: "ssh-internet",
    label: "SSH from internet",
    group: "input",
    packet: {
      ...base,
      src: "198.51.100.9",
      dst: "10.0.1.10",
      sport: 51111,
      dport: 22,
      proto: "tcp",
      direction: "input",
    },
    expect: { verdict: "drop", matchedRuleId: "in-ext-drop" },
  },
  {
    id: "https-public",
    label: "HTTPS public",
    group: "input",
    packet: {
      ...base,
      src: "198.51.100.40",
      dst: "10.0.1.10",
      sport: 52301,
      dport: 443,
      proto: "tcp",
      direction: "input",
    },
    expect: { verdict: "accept", matchedRuleId: "in-https" },
  },
  {
    id: "http-jump",
    label: "HTTP via jump",
    group: "input",
    packet: {
      ...base,
      src: "203.0.113.80",
      dst: "10.0.1.10",
      sport: 45000,
      dport: 80,
      proto: "tcp",
      direction: "input",
    },
    expect: { verdict: "accept", matchedRuleId: "svc-http" },
  },
  {
    id: "pg-app",
    label: "Postgres from app",
    group: "input",
    packet: {
      ...base,
      src: "10.0.4.12",
      dst: "10.0.1.20",
      sport: 40122,
      dport: 5432,
      proto: "tcp",
      direction: "input",
    },
    expect: { verdict: "accept", matchedRuleId: "in-pg" },
  },
  {
    id: "pg-internet",
    label: "Postgres from internet",
    group: "input",
    packet: {
      ...base,
      src: "203.0.113.9",
      dst: "10.0.1.20",
      sport: 44001,
      dport: 5432,
      proto: "tcp",
      direction: "input",
    },
    expect: { verdict: "drop", matchedRuleId: "in-ext-drop" },
  },
  {
    id: "smb-scan",
    label: "SMB scanner",
    group: "input",
    packet: {
      ...base,
      src: "10.0.9.9",
      dst: "10.0.1.10",
      sport: 40001,
      dport: 445,
      proto: "tcp",
      direction: "input",
    },
    expect: { verdict: "drop", matchedRuleId: "in-smb" },
  },
  {
    id: "loopback",
    label: "Loopback",
    group: "input",
    packet: {
      ...base,
      src: "127.0.0.1",
      dst: "127.0.0.1",
      sport: 50000,
      dport: 8080,
      proto: "tcp",
      iif: "lo",
      oif: "lo",
      direction: "input",
    },
    expect: { verdict: "accept", matchedRuleId: "in-lo" },
  },
  {
    id: "established",
    label: "Established flow",
    group: "input",
    packet: {
      ...base,
      src: "203.0.113.9",
      dst: "10.0.1.10",
      sport: 44321,
      dport: 22,
      proto: "tcp",
      direction: "input",
      ctState: "established",
    },
    expect: { verdict: "accept", matchedRuleId: "in-est" },
  },
  {
    id: "invalid-ct",
    label: "Invalid conntrack",
    group: "input",
    packet: {
      ...base,
      src: "10.0.2.15",
      dst: "10.0.1.10",
      sport: 40002,
      dport: 22,
      proto: "tcp",
      direction: "input",
      ctState: "invalid",
    },
    expect: { verdict: "drop", matchedRuleId: "in-invalid" },
  },
  {
    id: "icmp-mgmt",
    label: "ICMP from mgmt",
    group: "input",
    packet: {
      ...base,
      src: "10.0.2.15",
      dst: "10.0.1.10",
      sport: 0,
      dport: 0,
      proto: "icmp",
      direction: "input",
    },
    expect: { verdict: "accept", matchedRuleId: "in-icmp" },
  },
  {
    id: "shadow-dns",
    label: "Shadowed DNS",
    group: "shadow",
    packet: {
      ...base,
      src: "203.0.113.50",
      dst: "10.0.1.53",
      sport: 53001,
      dport: 53,
      proto: "udp",
      direction: "input",
    },
    expect: { verdict: "drop", matchedRuleId: "in-ext-drop" },
  },
  {
    id: "shadow-metrics",
    label: "Shadowed metrics",
    group: "shadow",
    packet: {
      ...base,
      src: "203.0.113.20",
      dst: "10.0.1.10",
      sport: 51000,
      dport: 9100,
      proto: "tcp",
      direction: "input",
    },
    expect: { verdict: "drop", matchedRuleId: "in-ext-drop" },
  },
  {
    id: "fw-app-db",
    label: "Forward app→db",
    group: "forward",
    packet: {
      ...base,
      src: "10.0.4.12",
      dst: "10.0.1.20",
      sport: 40200,
      dport: 5432,
      proto: "tcp",
      direction: "forward",
    },
    expect: { verdict: "accept", matchedRuleId: "fw-app-db" },
  },
  {
    id: "fw-other-db",
    label: "Forward alien→db",
    group: "forward",
    packet: {
      ...base,
      src: "10.0.9.9",
      dst: "10.0.1.20",
      sport: 40201,
      dport: 5432,
      proto: "tcp",
      direction: "forward",
    },
    expect: { verdict: "drop", matchedRuleId: "fw-deny-db-world" },
  },
  {
    id: "out-smtp",
    label: "Outbound SMTP",
    group: "output",
    packet: {
      ...base,
      src: "10.0.1.10",
      dst: "198.51.100.25",
      sport: 45001,
      dport: 25,
      proto: "tcp",
      direction: "output",
    },
    expect: { verdict: "reject", matchedRuleId: "out-smtp" },
  },
  {
    id: "out-dns",
    label: "Outbound DNS",
    group: "output",
    packet: {
      ...base,
      src: "10.0.1.10",
      dst: "1.1.1.1",
      sport: 53002,
      dport: 53,
      proto: "udp",
      direction: "output",
    },
    expect: { verdict: "accept", matchedRuleId: "out-dns" },
  },
  {
    id: "out-https-policy",
    label: "Outbound HTTPS (policy)",
    group: "output",
    packet: {
      ...base,
      src: "10.0.1.10",
      dst: "203.0.113.10",
      sport: 45002,
      dport: 443,
      proto: "tcp",
      direction: "output",
    },
    expect: { verdict: "accept", matchedRuleId: null },
  },
  {
    id: "dns-internal",
    label: "DNS from mgmt",
    group: "input",
    packet: {
      ...base,
      src: "10.0.2.15",
      dst: "10.0.1.53",
      sport: 53010,
      dport: 53,
      proto: "udp",
      direction: "input",
    },
    expect: { verdict: "accept", matchedRuleId: "in-dns" },
  },
  {
    id: "input-policy-drop",
    label: "Unknown port (policy)",
    group: "input",
    packet: {
      ...base,
      src: "10.0.2.15",
      dst: "10.0.1.10",
      sport: 41000,
      dport: 9999,
      proto: "tcp",
      direction: "input",
    },
    expect: { verdict: "drop", matchedRuleId: null },
  },
];
