import { spawn } from "node:child_process";
import net from "node:net";
import { chromium } from "playwright";

const BASE = process.env.NETVERDICT_URL ?? "http://127.0.0.1:3847";
const PORT = Number(new URL(BASE).port || 80);
const results = [];

function ok(name, pass, detail = "") {
  results.push({ name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}

function portOpen(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host: "127.0.0.1" }, () => {
      socket.end();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
  });
}

async function waitForHttp(url, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // server still booting
    }
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw new Error(`server did not become ready: ${url}`);
}

let server = null;

async function ensureServer() {
  if (await portOpen(PORT)) {
    await waitForHttp(BASE, 5_000);
    console.log(`using existing server at ${BASE}`);
    return;
  }
  console.log(`starting dev server on :${PORT}`);
  server = spawn("npm", ["run", "dev"], {
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout?.on("data", (chunk) => process.stdout.write(chunk));
  server.stderr?.on("data", (chunk) => process.stderr.write(chunk));
  await waitForHttp(BASE, 90_000);
}

function stopServer() {
  if (!server?.pid) return;
  try {
    process.kill(-server.pid, "SIGTERM");
  } catch {
    try {
      server.kill("SIGTERM");
    } catch {
      // already gone
    }
  }
}

const scenarios = [
  ["SSH from mgmt", "accept", "in-ssh"],
  ["SSH from internet", "drop", "in-ext-drop"],
  ["HTTPS public", "accept", "in-https"],
  ["HTTP via jump", "accept", "svc-http"],
  ["Postgres from app", "accept", "in-pg"],
  ["Postgres from internet", "drop", "in-ext-drop"],
  ["SMB scanner", "drop", "in-smb"],
  ["Loopback", "accept", "in-lo"],
  ["Established flow", "accept", "in-est"],
  ["Invalid conntrack", "drop", "in-invalid"],
  ["ICMP from mgmt", "accept", "in-icmp"],
  ["Shadowed DNS", "drop", "in-ext-drop"],
  ["Shadowed metrics", "drop", "in-ext-drop"],
  ["Forward app→db", "accept", "fw-app-db"],
  ["Forward alien→db", "drop", "fw-deny-db-world"],
  ["Outbound SMTP", "reject", "out-smtp"],
  ["Outbound DNS", "accept", "out-dns"],
  ["Outbound HTTPS (policy)", "accept", null],
  ["DNS from mgmt", "accept", "in-dns"],
  ["Unknown port (policy)", "drop", null],
];

let browser;

try {
  await ensureServer();
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 960 } });
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: BASE });
  const page = await context.newPage();
  await page.goto(BASE, { waitUntil: "networkidle" });
  ok("brand visible", await page.getByText("NetVerdict").first().isVisible());
  ok(
    "tabs present",
    (await page.getByRole("button", { name: "Probe", exact: true }).count()) > 0 &&
      (await page.getByRole("button", { name: /Policy/ }).count()) > 0 &&
      (await page.getByRole("button", { name: /Audit/ }).count()) > 0 &&
      (await page.getByRole("button", { name: /Suite/ }).count()) > 0,
  );
  ok("scenario count", await page.getByText("20 scenarios").isVisible());

  for (const [label, verdict, ruleId] of scenarios) {
    await page.getByRole("button", { name: label, exact: true }).click();
    const badge = page.getByTestId("verdict-pill");
    await badge.waitFor({ state: "visible", timeout: 3000 });
    const text = (await badge.textContent())?.trim().toLowerCase() ?? "";
    const reason = ruleId
      ? page.getByText(new RegExp(`Matched ${ruleId}\\b`))
      : page.getByText("No rule matched — chain policy applied.");
    const reasonVisible = await reason.isVisible();
    ok(
      `scenario: ${label}`,
      text === verdict && reasonVisible,
      [
        text === verdict ? "" : `got "${text}" want "${verdict}"`,
        reasonVisible ? "" : "matched rule not shown",
      ]
        .filter(Boolean)
        .join("; "),
    );
  }

  await page.getByRole("button", { name: "DNS from mgmt", exact: true }).click();
  ok(
    "internal DNS is not dead",
    ((await page.getByTestId("verdict-pill").textContent()) ?? "").trim().toLowerCase() ===
      "accept" && (await page.getByText("in-dns", { exact: true }).count()) > 0,
  );

  await page.getByRole("button", { name: "SSH from mgmt", exact: true }).click();
  await page.getByRole("combobox", { name: "direction" }).selectOption("forward");
  await page.getByTestId("verdict-pill").waitFor({ state: "visible" });
  ok(
    "direction changes the hook",
    ((await page.getByTestId("verdict-pill").textContent()) ?? "").trim().toLowerCase() ===
      "drop",
  );
  ok("custom packet clears preset", await page.getByText("custom").isVisible());

  await page.getByRole("combobox", { name: "proto" }).selectOption("icmp");
  ok(
    "ICMP zeroes ports",
    (await page.getByRole("spinbutton", { name: "sport" }).inputValue()) === "0" &&
      (await page.getByRole("spinbutton", { name: "dport" }).inputValue()) === "0",
  );

  await page.getByRole("textbox", { name: "src", exact: true }).fill("999.1.1.1");
  await page.getByRole("textbox", { name: "dst", exact: true }).fill("01.2.3.4");
  await page.getByRole("spinbutton", { name: "sport" }).fill("70000");
  await page.getByRole("textbox", { name: "iif", exact: true }).fill("   ");
  ok(
    "invalid IP validation",
    await page.getByText("Source must be a valid IPv4 address.").isVisible(),
  );
  ok(
    "leading-zero IP rejected",
    await page.getByText("Destination must be a valid IPv4 address.").isVisible(),
  );
  ok("bad port rejected", await page.getByText("Sport must be 0–65535.").isVisible());
  ok(
    "blank interface rejected",
    await page.getByText("Ingress interface is required.").isVisible(),
  );
  ok(
    "copy disabled while invalid",
    await page.getByRole("button", { name: "Copy CLI" }).isDisabled(),
  );
  ok(
    "probe blocked while invalid",
    await page.getByText("Fix packet fields to run a probe.").isVisible(),
  );

  await page.getByRole("button", { name: "SSH from mgmt", exact: true }).click();
  await page.getByRole("textbox", { name: "iif", exact: true }).fill("eth0;id");
  await page.getByRole("button", { name: "Copy CLI" }).click();
  await page.getByRole("button", { name: "Copied CLI" }).waitFor({ timeout: 2000 });
  const cli = await page.evaluate(() => navigator.clipboard.readText());
  ok(
    "CLI export is shell-quoted",
    cli.includes("netverdict probe") &&
      cli.includes("--src 10.0.2.15") &&
      cli.includes("--iif 'eth0;id'") &&
      !cli.includes("--iif eth0;id"),
    cli,
  );

  await page.getByRole("button", { name: "Copy JSON" }).click();
  await page.getByRole("button", { name: "Copied JSON" }).waitFor({ timeout: 2000 });
  const json = await page.evaluate(() => navigator.clipboard.readText());
  let parsed = null;
  try {
    parsed = JSON.parse(json);
  } catch {
    parsed = null;
  }
  ok(
    "JSON export matches the probe",
    parsed?.verdict === "accept" &&
      parsed?.matchedRule === "in-ssh" &&
      parsed?.packet?.iif === "eth0;id",
  );

  await page.getByRole("button", { name: "Probe packet" }).click();
  ok("probe button keeps the verdict", await page.getByText(/Verdict/i).first().isVisible());

  await page.getByRole("button", { name: /Policy/ }).click();
  ok("policy INPUT", await page.getByText("INPUT", { exact: true }).first().isVisible());
  ok("policy FORWARD", await page.getByText("FORWARD", { exact: true }).first().isVisible());
  ok("policy OUTPUT", await page.getByText("OUTPUT", { exact: true }).first().isVisible());
  ok(
    "user chain is implicit return",
    (await page.getByTestId("chain-meta-services").textContent())?.includes("implicit return") ===
      true,
  );
  ok(
    "hook chain shows its policy",
    (await page.getByTestId("chain-meta-INPUT").textContent())?.includes("policy drop") === true,
  );

  await page.getByRole("button", { name: /Audit/ }).click();
  const metrics = page.locator('[data-testid="audit-finding"][data-rule="in-metrics"]');
  const dns = page.locator('[data-testid="audit-finding"][data-rule="in-dns"]');
  ok("metrics fully shadowed", await metrics.getByText("Shadowed by negated match").isVisible());
  ok("dns partially shadowed", await dns.getByText("Partially shadowed").isVisible());
  ok(
    "dns is not reported dead",
    (await dns.getByText(/not reachable|unreachable/i).count()) === 0,
  );
  ok("audit has two findings", (await page.getByTestId("audit-finding").count()) === 2);

  await metrics.getByRole("button", { name: "Probe shadowed path" }).click();
  await page.getByTestId("verdict-pill").waitFor({ state: "visible" });
  const probeTabActive =
    (await page.locator("button.tab", { hasText: /^Probe$/ }).getAttribute("data-active")) ===
    "true";
  ok(
    "metrics audit → drop",
    probeTabActive &&
      ((await page.getByTestId("verdict-pill").textContent()) ?? "").trim().toLowerCase() ===
        "drop",
  );

  await page.getByRole("button", { name: /Audit/ }).click();
  await dns.getByRole("button", { name: "Probe shadowed path" }).click();
  ok(
    "dns audit → external drop",
    ((await page.getByTestId("verdict-pill").textContent()) ?? "").trim().toLowerCase() ===
      "drop" && (await page.getByText("in-ext-drop", { exact: true }).count()) > 0,
  );

  await page.getByRole("button", { name: /Suite/ }).click();
  await page.getByRole("button", { name: /Run all/ }).click();
  ok("suite passed count", await page.getByText("20 passed").isVisible());
  ok("suite failed count", await page.getByText("0 failed").isVisible());
  ok("suite row count", (await page.getByTestId("suite-row").count()) === 20);
  await page.getByRole("button", { name: "Failures only" }).click();
  ok("suite failures empty", await page.getByText(/No failures/).isVisible());
  await page.getByRole("button", { name: "Show all" }).click();
  await page.locator('[data-testid="suite-row"][data-case="dns-internal"]').getByRole("button", { name: "Open in probe" }).click();
  ok(
    "suite opens internal DNS",
    ((await page.getByTestId("verdict-pill").textContent()) ?? "").trim().toLowerCase() ===
      "accept",
  );

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Shadowed DNS", exact: true }).click();
  ok(
    "mobile scenario",
    await page.getByText("NetVerdict").first().isVisible() &&
      ((await page.getByTestId("verdict-pill").textContent()) ?? "").trim().toLowerCase() ===
        "drop",
  );
  await page.getByRole("button", { name: /Suite/ }).click();
  ok("mobile suite", await page.getByText("20 passed").isVisible());
} catch (err) {
  ok("uncaught", false, String(err));
} finally {
  await browser?.close();
  stopServer();
}

const failed = results.filter((row) => !row.pass);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
