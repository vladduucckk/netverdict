/** IPv4 helpers for CIDR matching. */

// Canonical dotted decimal only. Rejects leading zeros, hex, and scientific
// notation — those forms are ambiguous across parsers (some treat 012 as octal).
const OCTET = "(?:0|[1-9]\\d{0,2})";
const IPV4_RE = new RegExp(`^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);

export function ipToInt(ip: string): number | null {
  const trimmed = ip.trim();
  if (!IPV4_RE.test(trimmed)) return null;
  const nums = trimmed.split(".").map((part) => Number(part));
  if (nums.some((n) => n > 255)) return null;
  return (
    (((nums[0]! << 24) >>> 0) +
      (nums[1]! << 16) +
      (nums[2]! << 8) +
      nums[3]!) >>>
    0
  );
}

export function intToIp(value: number): string {
  const n = value >>> 0;
  return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

export function isValidIpv4(ip: string): boolean {
  return ipToInt(ip) !== null;
}

export type ParsedCidr = {
  network: number;
  mask: number;
  prefix: number;
  negate: boolean;
  raw: string;
};

export function parseCidr(cidr: string): ParsedCidr | null {
  const trimmed = cidr.trim();
  if (!trimmed) return null;
  const negate = trimmed.startsWith("!");
  const body = (negate ? trimmed.slice(1) : trimmed).trim();
  // Internal whitespace and extra slashes are not a CIDR.
  if (!body || /\s/.test(body)) return null;
  const parts = body.split("/");
  if (parts.length > 2) return null;
  const [ip, prefixStr] = parts;
  if (!ip) return null;
  const ipInt = ipToInt(ip);
  if (ipInt === null) return null;
  if (prefixStr !== undefined && !/^(?:0|[1-9]\d?)$/.test(prefixStr)) return null;
  const prefix = prefixStr === undefined ? 32 : Number(prefixStr);
  if (prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return {
    network: (ipInt & mask) >>> 0,
    mask,
    prefix,
    negate,
    raw: trimmed,
  };
}

/** A few concrete addresses inside a CIDR, or outside it when the CIDR is negated. */
export function ipsInCidr(cidr: string): string[] {
  const parsed = parseCidr(cidr);
  if (!parsed) return [];

  if (!parsed.negate) {
    const ips = [parsed.network];
    const hostMask = parsed.prefix === 0 ? 0xffffffff : (~parsed.mask) >>> 0;
    const last = (parsed.network | hostMask) >>> 0;
    if (last !== parsed.network) ips.push(last);
    if (parsed.prefix < 32) {
      const next = (parsed.network + 1) >>> 0;
      if (((next & parsed.mask) >>> 0) === parsed.network && next !== last) {
        ips.push(next);
      }
    }
    return ips.map(intToIp);
  }

  // Nothing is outside 0.0.0.0/0.
  if (parsed.prefix === 0) return [];

  const candidates = [
    (parsed.network ^ 0x80000000) >>> 0,
    0,
    0xffffffff,
    0x0a000001,
    0xcb007132,
    0xc6336409,
  ];
  const out: string[] = [];
  for (const n of candidates) {
    if (((n & parsed.mask) >>> 0) === parsed.network) continue;
    const ip = intToIp(n);
    if (!out.includes(ip)) out.push(ip);
  }
  return out;
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const parsed = parseCidr(cidr);
  const ipInt = ipToInt(ip);
  if (!parsed || ipInt === null) return false;
  const inNet = ((ipInt & parsed.mask) >>> 0) === parsed.network;
  return parsed.negate ? !inNet : inNet;
}

function rangesOverlap(
  aNet: number,
  aMask: number,
  bNet: number,
  bMask: number,
): boolean {
  const mask = aMask & bMask;
  return ((aNet & mask) >>> 0) === ((bNet & mask) >>> 0);
}

/** True if every IP matched by `inner` is also matched by `outer`. */
export function cidrCovers(
  outer: string | undefined,
  inner: string | undefined,
): boolean {
  if (!outer) return true; // no constraint covers all
  if (!inner) return false; // constrained outer cannot cover unconstrained inner

  const o = parseCidr(outer);
  const i = parseCidr(inner);
  if (!o || !i) return false;

  // Positive ⊇ positive
  if (!o.negate && !i.negate) {
    if (o.prefix > i.prefix) return false;
    return ((i.network & o.mask) >>> 0) === o.network;
  }

  // !A covers B  iff  B does not overlap A  (every addr in B is outside A)
  if (o.negate && !i.negate) {
    return !rangesOverlap(o.network, o.mask, i.network, i.mask);
  }

  // A covers !B — only if A is the universal set; we don't model that here.
  // !A covers !B — conservative skip (hard to reason without universe split).
  return false;
}
