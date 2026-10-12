import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import type { TrustReport } from "../src/report.js";
import {
	canonicalize,
	keygen,
	parseTrustedKeys,
	sha256Hex,
	signBadge,
	verifyBadge,
} from "../src/sign.js";

const execFileAsync = promisify(execFile);
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(repoRoot, "dist", "cli.js");

function report(): TrustReport {
	return {
		tool: "sigil",
		toolVersion: "0.1.0",
		target: "fixture",
		targetKind: "local",
		server: { name: "fixture-server", version: "0.1.0" },
		riskScore: 5,
		riskLevel: "low",
		counts: { critical: 0, major: 0, minor: 0, info: 0 },
		static: {
			root: "/tmp/x",
			packageName: "fixture-server",
			packageVersion: "0.1.0",
			toolSource: "runtime",
			toolCount: 0,
			findings: [],
			dependencies: {
				ran: false,
				critical: 0,
				high: 0,
				moderate: 0,
				low: 0,
				info: 0,
			},
			durationMs: 1,
		},
		behavioral: null,
		behavioralError: null,
		durationMs: 1,
	} as TrustReport;
}

function signed() {
	const dir = mkdtempSync(join(tmpdir(), "sigil-trust-"));
	const k = keygen(dir);
	return { ...k, dir, badge: signBadge(report(), k.privatePath) };
}

describe("verifyBadge with a trusted key set", () => {
	it("without a trusted set: valid signature, signer not asserted", () => {
		const { badge } = signed();
		const r = verifyBadge(badge);
		expect(r.ok).toBe(true);
		expect(r.trustedSigner).toBeUndefined();
	});

	it("accepts a badge from a trusted key (case-insensitive)", () => {
		const { badge, keyId } = signed();
		const r = verifyBadge(badge, { trustedKeyIds: [keyId.toUpperCase()] });
		expect(r).toEqual({
			ok: true,
			trustedSigner: true,
			reason:
				"signature valid from a trusted key; evalHash commits to the scored content",
		});
	});

	it("rejects a self-signed 'passed' badge from an unknown key", () => {
		const { badge } = signed();
		const other = signed();
		const r = verifyBadge(badge, { trustedKeyIds: new Set([other.keyId]) });
		expect(r.ok).toBe(false);
		expect(r.trustedSigner).toBe(false);
		expect(r.reason).toContain("not in the trusted key set");
	});

	it("an empty trusted set trusts nobody", () => {
		const { badge } = signed();
		expect(verifyBadge(badge, { trustedKeyIds: [] }).ok).toBe(false);
	});

	it("a forged keyId cannot borrow a trusted id", () => {
		const trustedKey = signed();
		const attacker = signed();
		const forged = { ...attacker.badge, keyId: trustedKey.keyId };
		const r = verifyBadge(forged, { trustedKeyIds: [trustedKey.keyId] });
		expect(r.ok).toBe(false);
		expect(r.reason).toContain("does not match the embedded public key");
	});

	it("a tampered badge fails before the trust check", () => {
		const { badge, keyId } = signed();
		const r = verifyBadge(
			{ ...badge, riskScore: 0 },
			{ trustedKeyIds: [keyId] },
		);
		expect(r.ok).toBe(false);
		expect(r.trustedSigner).toBeUndefined();
	});
});

describe("parseTrustedKeys", () => {
	it("parses id lists separated by commas, spaces and newlines", () => {
		const ids = parseTrustedKeys(
			"0123456789abcdef, FEDCBA9876543210\n\n aaaaaaaaaaaaaaaa ",
		);
		expect([...ids].sort()).toEqual([
			"0123456789abcdef",
			"aaaaaaaaaaaaaaaa",
			"fedcba9876543210",
		]);
	});

	it("parses a public-key file and re-derives the id from the key", () => {
		const { publicPath, keyId } = signed();
		const text = readFileSync(publicPath, "utf8");
		expect([...parseTrustedKeys(text)]).toEqual([keyId]);
		const pk = JSON.parse(text).publicKey;
		const lying = JSON.stringify({ keyId: "0000000000000000", publicKey: pk });
		expect([...parseTrustedKeys(lying)]).toEqual([
			sha256Hex(canonicalize(pk)).slice(0, 16),
		]);
	});

	it("parses JSON arrays of ids and objects", () => {
		const ids = parseTrustedKeys(
			'["0123456789abcdef", {"keyId": "1111111111111111"}]',
		);
		expect([...ids].sort()).toEqual(["0123456789abcdef", "1111111111111111"]);
	});

	it("rejects malformed entries", () => {
		expect(() => parseTrustedKeys("not-a-key-id")).toThrow(/invalid key id/);
		expect(() => parseTrustedKeys("[42]")).toThrow(/key ids or \{publicKey\}/);
		expect(() => parseTrustedKeys('{"nothing": true}')).toThrow();
		expect(() => parseTrustedKeys("0123456789abcde")).toThrow(/invalid key id/);
		expect(parseTrustedKeys("").size).toBe(0);
	});
});

async function verifyCli(args: string[], env: Record<string, string> = {}) {
	const home = mkdtempSync(join(tmpdir(), "sigil-home-"));
	try {
		const { stdout, stderr } = await execFileAsync(
			"node",
			[cli, "verify", ...args],
			{
				timeout: 60_000,
				env: {
					...process.env,
					HOME: home,
					USERPROFILE: home,
					NO_COLOR: "1",
					SIGIL_TRUSTED_KEYS: "",
					...env,
				},
			},
		);
		return { code: 0, out: stdout + stderr, home };
	} catch (error) {
		const e = error as { code?: number; stdout?: string; stderr?: string };
		return {
			code: e.code ?? 1,
			out: `${e.stdout ?? ""}${e.stderr ?? ""}`,
			home,
		};
	}
}

describe("sigil verify --offline (CLI)", { timeout: 60_000 }, () => {
	it("refuses an unknown signer by default", async () => {
		const { badge, dir } = signed();
		const file = join(dir, "badge.json");
		writeFileSync(file, JSON.stringify(badge));
		const r = await verifyCli([file, "--offline"]);
		expect(r.code).toBe(1);
		expect(r.out).toContain("untrusted signer");
	});

	it("accepts with --trusted-keys, SIGIL_TRUSTED_KEYS, or --allow-untrusted", async () => {
		const { badge, dir, keyId, publicPath } = signed();
		const file = join(dir, "badge.json");
		writeFileSync(file, JSON.stringify(badge));
		const viaFile = await verifyCli([
			file,
			"--offline",
			"--trusted-keys",
			publicPath,
		]);
		expect(viaFile.code).toBe(0);
		expect(viaFile.out).toContain(`signer: trusted key ${keyId}`);
		expect(
			(await verifyCli([file, "--offline"], { SIGIL_TRUSTED_KEYS: keyId }))
				.code,
		).toBe(0);
		const waived = await verifyCli([file, "--offline", "--allow-untrusted"]);
		expect(waived.code).toBe(0);
		expect(waived.out).toContain("UNVERIFIED");
	});

	it("rejects a badge whose key is not in a supplied trusted set", async () => {
		const { badge, dir } = signed();
		const other = signed();
		const file = join(dir, "badge.json");
		writeFileSync(file, JSON.stringify(badge));
		const r = await verifyCli([
			file,
			"--offline",
			"--trusted-keys",
			other.publicPath,
		]);
		expect(r.code).toBe(1);
		expect(r.out).toContain("not in the trusted key set");
	});

	it("trusts the user's own key from sigil keygen", async () => {
		const home = mkdtempSync(join(tmpdir(), "sigil-ownhome-"));
		const cfg = join(home, ".config", "sigil");
		mkdirSync(cfg, { recursive: true });
		const own = keygen(cfg);
		const badge = signBadge(report(), own.privatePath);
		const file = join(home, "badge.json");
		writeFileSync(file, JSON.stringify(badge));
		const { stdout } = await execFileAsync(
			"node",
			[cli, "verify", file, "--offline"],
			{
				timeout: 60_000,
				env: {
					...process.env,
					HOME: home,
					USERPROFILE: home,
					SIGIL_TRUSTED_KEYS: "",
				},
			},
		);
		expect(stdout).toContain(`signer: trusted key ${own.keyId}`);
	});
});
