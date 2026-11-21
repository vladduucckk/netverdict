import { describe, expect, it } from "vitest";
import { cidrCovers, intToIp, ipInCidr, ipToInt, ipsInCidr, parseCidr } from "./ip";

describe("strict IPv4", () => {
  it("accepts canonical addresses and surrounding whitespace", () => {
    expect(ipToInt("0.0.0.0")).toBe(0);
    expect(ipToInt("255.255.255.255")).toBe(4294967295);
    expect(ipToInt(" 10.0.0.1 ")).toBe((10 << 24) + 1);
    expect(intToIp((10 << 24) + 1)).toBe("10.0.0.1");
  });

  it("rejects ambiguous or truncated forms", () => {
    for (const bad of [
      "01.2.3.4",
      "1e1.0.0.1",
      "0x10.0.0.1",
      "10.0.0.",
      "10.0..1",
      "+10.0.0.1",
      "10.0.0.1/32",
      "10.0.0.256",
      "1.2.3",
      "",
      "10.0.0. 1",
    ]) {
      expect(ipToInt(bad), bad).toBeNull();
    }
  });
});

describe("CIDR parsing", () => {
  it("rejects malformed prefixes", () => {
    expect(parseCidr("10.0.0.0/33")).toBeNull();
    expect(parseCidr("10.0.0.0/08")).toBeNull();
    expect(parseCidr("10.0.0.0/8/1")).toBeNull();
    expect(parseCidr("10.0.0.0 /8")).toBeNull();
    expect(parseCidr("")).toBeNull();
    expect(parseCidr("!10.0.0.0/99")).toBeNull();
  });

  it("treats a bare address as /32 and keeps negation", () => {
    const host = parseCidr("10.1.2.3");
    expect(host?.prefix).toBe(32);
    expect(host?.negate).toBe(false);
    const negated = parseCidr("! 10.0.0.0/8");
    expect(negated?.negate).toBe(true);
    expect(negated?.prefix).toBe(8);
  });

  it("matches /0, /32, and negation", () => {
    expect(ipInCidr("0.0.0.0", "0.0.0.0/0")).toBe(true);
    expect(ipInCidr("255.255.255.255", "0.0.0.0/0")).toBe(true);
    expect(ipInCidr("1.2.3.4", "!0.0.0.0/0")).toBe(false);
    expect(ipInCidr("10.1.2.3", "10.1.2.3")).toBe(true);
    expect(ipInCidr("10.1.2.4", "10.1.2.3")).toBe(false);
    expect(ipInCidr("not-an-ip", "10.0.0.0/8")).toBe(false);
    expect(ipInCidr("10.0.0.1", "nope")).toBe(false);
  });

  it("offers concrete addresses inside and outside a prefix", () => {
    expect(ipsInCidr("10.0.4.0/24")).toEqual(
      expect.arrayContaining(["10.0.4.0", "10.0.4.1", "10.0.4.255"]),
    );
    expect(ipsInCidr("!0.0.0.0/0")).toEqual([]);
    for (const ip of ipsInCidr("!10.0.0.0/8")) {
      expect(ipInCidr(ip, "!10.0.0.0/8")).toBe(true);
    }
    for (const ip of ipsInCidr("192.0.2.0/24")) {
      expect(ipInCidr(ip, "192.0.2.0/24")).toBe(true);
    }
  });
});

describe("CIDR cover", () => {
  const samples = [
    "0.0.0.0",
    "10.0.0.0",
    "10.0.4.12",
    "10.255.255.255",
    "11.0.0.0",
    "127.0.0.1",
    "203.0.113.50",
    "255.255.255.255",
  ];

  it("never claims cover when a sample in the inner prefix falls outside", () => {
    const outers = ["10.0.0.0/8", "10.0.4.0/24", "!10.0.0.0/8", "0.0.0.0/0", "203.0.113.0/24"];
    const inners = ["10.0.4.0/24", "10.0.4.12/32", "11.0.0.0/8", "203.0.113.0/24", "0.0.0.0/0"];
    for (const outer of outers) {
      for (const inner of inners) {
        if (!cidrCovers(outer, inner)) continue;
        for (const ip of samples) {
          if (!ipInCidr(ip, inner)) continue;
          expect(ipInCidr(ip, outer), `${outer} covers ${inner}, but ${ip} escaped`).toBe(
            true,
          );
        }
      }
    }
  });

  it("does not let a negated prefix cover an overlapping or unconstrained range", () => {
    expect(cidrCovers("!10.0.0.0/8", "10.0.4.0/24")).toBe(false);
    expect(cidrCovers("!10.0.0.0/8", undefined)).toBe(false);
    expect(cidrCovers(undefined, "10.0.0.0/8")).toBe(true);
    expect(cidrCovers("!0.0.0.0/0", "203.0.113.0/24")).toBe(false);
  });
});
