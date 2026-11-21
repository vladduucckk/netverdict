import { isValidIpv4 } from "./ip";
import type { Packet } from "./policy";

export type FieldError = {
  field: keyof Packet | "general";
  message: string;
};

export function validatePacket(packet: Packet): FieldError[] {
  const errors: FieldError[] = [];
  const src = packet.src.trim();
  const dst = packet.dst.trim();

  if (!isValidIpv4(src)) {
    errors.push({ field: "src", message: "Source must be a valid IPv4 address." });
  }
  if (!isValidIpv4(dst)) {
    errors.push({ field: "dst", message: "Destination must be a valid IPv4 address." });
  }
  if (!Number.isInteger(packet.sport) || packet.sport < 0 || packet.sport > 65535) {
    errors.push({ field: "sport", message: "Sport must be 0–65535." });
  }
  if (!Number.isInteger(packet.dport) || packet.dport < 0 || packet.dport > 65535) {
    errors.push({ field: "dport", message: "Dport must be 0–65535." });
  }
  if (!packet.iif.trim()) {
    errors.push({ field: "iif", message: "Ingress interface is required." });
  }
  if (!packet.oif.trim()) {
    errors.push({ field: "oif", message: "Egress interface is required." });
  }

  // ICMP ports are conventional zeros — not a hard error. UI normalizes on proto change.
  return errors;
}
