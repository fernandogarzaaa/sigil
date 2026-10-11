#!/usr/bin/env node
/**
 * sigil: the Sigil CLI.
 *
 * Commands:
 *   sigil scan <target> [options]   scan an MCP server
 *   sigil keygen [--out <dir>]       generate an Ed25519 signing key
 *   sigil verify <badge.json>        verify a signed trust badge
 *   sigil publish --badge <file>     submit a badge to the trust index
 *
 * Exit codes: 0 = scan passed the risk gate; 2 = risk at or above --fail-on;
 * 1 = operational error (bad args, unresolvable target, IO failure).
 */

import {
	mkdtempSync,
	readFileSync,
	realpathSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveArtifact } from "./artifact.js";
import { evaluateMcpServer } from "./behavioral/index.js";
import { INDEX_REPO, publishBadge } from "./publish.js";
import {
	fetchManifest,
	type IndexManifest,
	installCommandFor,
	type ManifestBadge,
	resolvePin,
} from "./registry.js";
import {
	assembleReport,
	RISK_LEVELS,
	type RiskLevel,
	renderHumanSummary,
} from "./report.js";
import { classifyTarget, resolveTarget, type TargetKind } from "./resolve.js";
import {
	keygen,
	signBadge,
	signRevocation,
	type TrustBadge,
	type TrustRevocation,
	verifyBadge,
	verifyRevocation,
} from "./sign.js";
import { readManifest, runStaticPass } from "./static/index.js";

function packageVersion(): string {
	try {
		const here = dirname(fileURLToPath(import.meta.url));
		const pkg = JSON.parse(
			readFileSync(join(here, "..", "package.json"), "utf8"),
		) as {
			version?: string;
		};
		return typeof pkg.version === "string" ? pkg.version : "0.0.0";
	} catch {
		return "0.0.0";
	}
}

const VERSION = packageVersion();

function printHelp(): void {
	console.log(`sigil ${VERSION}: trust scanning for MCP servers.

Usage:
  sigil scan <target> [options]   Scan an MCP server.
    <target> is a local directory, an npm package spec (name[@version]),
    or a git URL (https://..., git@..., or owner/repo).
    --json            print the full JSON report instead of the summary
    --sign            sign a trust badge with your key (see keygen)
    --key <path>      private key file for --sign
    --badge-out <path>  write the badge JSON to a file (implies --sign)
    --fail-on <level> exit 2 when the risk level reaches this (default: high)
                      levels: low, medium, high, critical
    --no-fuzz         skip the fuzz oracle in the behavioral pass
    --skip-audit      skip the npm audit in the static pass
    --timeout <ms>    per-call timeout for the behavioral pass (default 5000)
    --publish         submit the signed badge to the public trust index
                      (implies --sign; needs the GitHub CLI, gh, authenticated)

  sigil keygen [--out <dir>]      Generate an Ed25519 signing key.
  sigil verify <badge.json> [--offline]
      Verify a signed trust badge. Unless --offline, also checks the badge's
      status (active / superseded / revoked) against the public trust index.
  sigil publish --badge <file> [--repo <owner/repo>]
      Submit a signed badge to the public trust index
      (default repo: ${INDEX_REPO}) by opening a pull request.
      The badge is verified locally first; nothing is submitted when it
      is invalid. Needs the GitHub CLI (gh) installed and authenticated.
  sigil pin <server>[@<version>] [--index-url <url>]
      Resolve the verified install for an indexed server. Prints the exact
      install command for the newest active version (or the named version).
      Refuses revoked versions; warns on superseded ones.
  sigil install <server>[@<version>] [--dry-run] [--index-url <url>]
      Install the verified version (npm). Shows the badge summary first;
      --dry-run prints the command without running it.
  sigil revoke --server <s> --version <v> --reason <r>
      --key <keyfile> [--out <file>]
      Sign a badge revocation with the project maintainer key. Submit the
      resulting JSON as revocations/<server>/<version>.json via PR.

Exit codes: 0 passed the gate (or the command succeeded), 2 risk at/above --fail-on
or a revoked badge on verify, 1 operational error.

A passing scan is not a guarantee: static checks are heuristics with false
positives, and the behavioral pass only exercises what it can reach.`);
}

interface ScanOptions {
	json: boolean;
	sign: boolean;
	keyPath?: string;
	badgeOut?: string;
	publish: boolean;
	failOn: RiskLevel;
	fuzz: boolean;
	skipAudit: boolean;
	timeoutMs: number;
}

function parseScanArgs(args: string[]): {
	target: string;
	options: ScanOptions;
} {
	const options: ScanOptions = {
		json: false,
		sign: false,
		publish: false,
		failOn: "high",
		fuzz: true,
		skipAudit: false,
		timeoutMs: 5000,
	};
	let target: string | undefined;
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg === undefined) continue;
		if (arg === "--json") options.json = true;
		else if (arg === "--sign") options.sign = true;
		else if (arg === "--key") {
			const value = args[++i];
			if (value === undefined) throw new Error("--key needs a path");
			options.keyPath = value;
		} else if (arg === "--badge-out") {
			options.badgeOut = args[++i];
			options.sign = true;
		} else if (arg === "--fail-on") {
			const level = args[++i] as RiskLevel | undefined;
			if (level === undefined) throw new Error("--fail-on needs a level");
			if (!RISK_LEVELS.includes(level)) {
				throw new Error(`--fail-on must be one of ${RISK_LEVELS.join(", ")}`);
			}
			options.failOn = level;
		} else if (arg === "--no-fuzz") options.fuzz = false;
		else if (arg === "--skip-audit") options.skipAudit = true;
		else if (arg === "--publish") {
			options.publish = true;
			options.sign = true;
		} else if (arg === "--timeout") {
			const rawMs = args[++i];
			if (rawMs === undefined) throw new Error("--timeout needs a value");
			const ms = Number(rawMs);
			if (!Number.isFinite(ms) || ms <= 0)
				throw new Error("--timeout must be a positive number");
			options.timeoutMs = ms;
		} else if (arg.startsWith("--")) {
			throw new Error(`unknown flag ${arg}`);
		} else if (target === undefined) {
			target = arg;
		} else {
			throw new Error(`unexpected argument ${arg}`);
		}
	}
	if (target === undefined)
		throw new Error("scan needs a target: sigil scan <target>");
	if (
		options.keyPath === undefined &&
		options.badgeOut === undefined &&
		options.sign
	) {
		// --sign without --key uses the default key location; fine.
	}
	return { target, options };
}

const LEVEL_RANK: Record<RiskLevel, number> = {
	low: 0,
	medium: 1,
	high: 2,
	critical: 3,
};

async function cmdScan(rawArgs: string[]): Promise<number> {
	const started = Date.now();
	const { target, options } = parseScanArgs(rawArgs);
	const kind: TargetKind = classifyTarget(target);

	const resolved = await resolveTarget(target);
	try {
		const manifest = readManifest(resolved.dir);

		// Behavioral pass: spawn the server entry over stdio. When the server
		// cannot be started, the scan continues with the static pass only and
		// says so in the report.
		let behavioral: Awaited<ReturnType<typeof evaluateMcpServer>> | null = null;
		let behavioralError: string | null = null;
		if (manifest.entry) {
			const stdioTarget = `node "${manifest.entry}"`;
			try {
				behavioral = await evaluateMcpServer(stdioTarget, {
					connect: { cwd: manifest.root },
					fuzz: options.fuzz ? { timeoutMs: options.timeoutMs } : false,
				});
			} catch (error) {
				behavioralError =
					error instanceof Error ? error.message : String(error);
			}
		} else {
			behavioralError =
				"no launchable server entry found (bin/main/conventional file)";
		}

		const staticReport = await runStaticPass(manifest.root, {
			runtimeTools: behavioral?.tools,
			skipAudit: options.skipAudit,
			noBehavioral: behavioral === null,
		});

		const report = assembleReport({
			toolVersion: VERSION,
			target,
			targetKind: kind,
			server:
				behavioral?.server ??
				(manifest.name
					? { name: manifest.name, version: manifest.version ?? "unknown" }
					: null),
			artifact: await resolveArtifact(target, kind, resolved.dir),
			static: staticReport,
			behavioral,
			behavioralError,
			durationMs: Date.now() - started,
		});

		if (options.json) {
			console.log(JSON.stringify(report, null, 2));
		} else {
			process.stdout.write(renderHumanSummary(report));
		}

		if (options.sign || options.badgeOut) {
			const badge = signBadge(report, options.keyPath);
			const badgeJson = JSON.stringify(badge, null, 2);
			let badgePath: string | undefined;
			if (options.badgeOut) {
				badgePath = resolve(options.badgeOut);
				writeFileSync(badgePath, `${badgeJson}\n`);
				if (!options.json) console.log(`badge written to ${badgePath}`);
			} else if (options.publish) {
				const dir = mkdtempSync(join(tmpdir(), "sigil-badge-"));
				badgePath = join(dir, "badge.json");
				writeFileSync(badgePath, `${badgeJson}\n`);
			} else {
				console.log(badgeJson);
			}
			if (options.publish && badgePath) {
				const result = await publishBadge(badgePath, {});
				console.log(`badge submitted: ${result.prUrl}`);
			}
		}

		const levelRank = LEVEL_RANK[report.riskLevel] ?? 0;
		const failRank = LEVEL_RANK[options.failOn] ?? 0;
		return levelRank >= failRank ? 2 : 0;
	} finally {
		resolved.cleanup();
	}
}

function cmdKeygen(rawArgs: string[]): number {
	let out: string | undefined;
	for (let i = 0; i < rawArgs.length; i++) {
		if (rawArgs[i] === "--out") {
			out = rawArgs[++i];
			if (out === undefined) throw new Error("--out needs a directory");
		} else throw new Error(`unknown flag ${rawArgs[i]}`);
	}
	const { keyId, privatePath, publicPath } = keygen(out);
	console.log(`key id: ${keyId}`);
	console.log(`private key: ${privatePath} (mode 0600: keep it secret)`);
	console.log(`public key:  ${publicPath}`);
	return 0;
}

function cmdVerify(rawArgs: string[]): Promise<number> {
	let badgePath: string | undefined;
	let offline = false;
	let indexUrl: string | undefined;
	for (let i = 0; i < rawArgs.length; i++) {
		const arg = rawArgs[i];
		if (arg === "--offline") offline = true;
		else if (arg === "--index-url") {
			indexUrl = rawArgs[++i];
			if (indexUrl === undefined) throw new Error("--index-url needs a URL");
		} else if (arg?.startsWith("--")) {
			throw new Error(`unknown flag ${arg}`);
		} else if (badgePath === undefined) {
			badgePath = arg;
		} else {
			throw new Error(`unexpected argument ${arg}`);
		}
	}
	if (badgePath === undefined) {
		throw new Error("verify needs a badge file: sigil verify <badge.json>");
	}
	const badge = JSON.parse(
		readFileSync(resolve(badgePath), "utf8"),
	) as TrustBadge;
	const result = verifyBadge(badge);
	if (!result.ok) {
		console.error(`invalid badge: ${result.reason}`);
		return Promise.resolve(1);
	}
	console.log(
		`valid badge: ${badge.server}@${badge.version} risk ${badge.riskScore}/100 (${badge.riskLevel}), key ${badge.keyId}`,
	);
	if (offline) return Promise.resolve(0);
	// Index status check: revoked badges must not be trusted.
	return (async () => {
		let manifest: IndexManifest | undefined;
		try {
			manifest = await fetchManifest(indexUrl);
		} catch (error) {
			console.log(
				`(trust index unreachable; local verification only: ${error instanceof Error ? error.message : String(error)})`,
			);
			return 0;
		}
		const entry = manifest.badges.find(
			(b) => b.server === badge.server && b.version === badge.version,
		);
		if (!entry) {
			console.log("(not indexed; local verification only)");
			return 0;
		}
		if (entry.status === "revoked") {
			const reason = entry.revocationReason
				? `: ${entry.revocationReason}`
				: "";
			console.error(
				`REVOKED: ${badge.server}@${badge.version} was revoked${reason}`,
			);
			return 2;
		}
		if (entry.status === "superseded") {
			console.log(
				`warning: ${badge.server}@${badge.version} is superseded by a newer indexed version`,
			);
		} else {
			console.log(`indexed: status ${entry.status} on the public trust index`);
		}
		return 0;
	})();
}

function parseServerAtVersion(raw: string): {
	server: string;
	version?: string;
} {
	const at = raw.lastIndexOf("@");
	// A leading @ means an npm scope (e.g. @scope/name), not a version split.
	if (at > 0) {
		const server = raw.slice(0, at);
		const version = raw.slice(at + 1);
		if (!server || !version) {
			throw new Error(`expected <server>[@<version>], got "${raw}"`);
		}
		return { server, version };
	}
	if (!raw) throw new Error("expected <server>[@<version>]");
	return { server: raw };
}

function printPinResolution(
	badge: ManifestBadge,
	explicitVersion: boolean,
): void {
	const fc = badge.findingCounts;
	console.log(`sigil pin: ${badge.server}@${badge.version}`);
	console.log(`  install:   ${installCommandFor(badge)}`);
	const integrity = badge.artifact?.integrity;
	console.log(`  integrity: ${integrity ?? "(not recorded)"}`);
	console.log(
		`  risk:      ${badge.riskScore}/100 (${badge.riskLevel}) — ${fc.critical} critical, ${fc.major} major, ${fc.minor} minor, ${fc.info} info`,
	);
	console.log(
		`  key:       ${badge.keyId}, issued ${badge.issuedAt.slice(0, 10)}`,
	);
	console.log(`  status:    ${badge.status}`);
	if (badge.status === "superseded" && explicitVersion) {
		console.log(
			"  warning: this version is superseded by a newer indexed version",
		);
	}
}

async function cmdPin(rawArgs: string[]): Promise<number> {
	let target: string | undefined;
	let indexUrl: string | undefined;
	for (let i = 0; i < rawArgs.length; i++) {
		const arg = rawArgs[i];
		if (arg === "--index-url") {
			indexUrl = rawArgs[++i];
			if (indexUrl === undefined) throw new Error("--index-url needs a URL");
		} else if (arg?.startsWith("--")) {
			throw new Error(`unknown flag ${arg}`);
		} else if (target === undefined) {
			target = arg;
		} else {
			throw new Error(`unexpected argument ${arg}`);
		}
	}
	if (target === undefined) {
		throw new Error("pin needs a server: sigil pin <server>[@<version>]");
	}
	const { server, version } = parseServerAtVersion(target);
	const manifest = await fetchManifest(indexUrl);
	const { badge, explicitVersion } = resolvePin(manifest, server, version);
	printPinResolution(badge, explicitVersion);
	return 0;
}

async function cmdInstall(rawArgs: string[]): Promise<number> {
	let target: string | undefined;
	let indexUrl: string | undefined;
	let dryRun = false;
	for (let i = 0; i < rawArgs.length; i++) {
		const arg = rawArgs[i];
		if (arg === "--index-url") {
			indexUrl = rawArgs[++i];
			if (indexUrl === undefined) throw new Error("--index-url needs a URL");
		} else if (arg === "--dry-run") {
			dryRun = true;
		} else if (arg?.startsWith("--")) {
			throw new Error(`unknown flag ${arg}`);
		} else if (target === undefined) {
			target = arg;
		} else {
			throw new Error(`unexpected argument ${arg}`);
		}
	}
	if (target === undefined) {
		throw new Error(
			"install needs a server: sigil install <server>[@<version>]",
		);
	}
	const { server, version } = parseServerAtVersion(target);
	const manifest = await fetchManifest(indexUrl);
	const { badge, explicitVersion } = resolvePin(manifest, server, version);
	printPinResolution(badge, explicitVersion);
	const command = installCommandFor(badge);
	if (dryRun) {
		console.log(`dry run: would execute: ${command}`);
		return 0;
	}
	const spec = badge.artifact?.spec;
	if (!spec) throw new Error("resolved badge has no installable artifact");
	console.log(`installing ${spec} ...`);
	const { spawn } = await import("node:child_process");
	await new Promise<void>((resolvePromise, reject) => {
		const child = spawn("npm", ["install", "-g", spec], {
			stdio: "inherit",
		});
		child.on("error", (error) => {
			reject(new Error(`could not start npm: ${error.message}`));
		});
		child.on("close", (code) => {
			if (code === 0) resolvePromise();
			else reject(new Error(`npm install exited with code ${code}`));
		});
	});
	console.log(`installed ${spec}`);
	return 0;
}

function cmdRevoke(rawArgs: string[]): number {
	let server: string | undefined;
	let version: string | undefined;
	let reason: string | undefined;
	let keyPath: string | undefined;
	let outPath: string | undefined;
	for (let i = 0; i < rawArgs.length; i++) {
		const arg = rawArgs[i];
		if (arg === "--server") {
			server = rawArgs[++i];
			if (server === undefined) throw new Error("--server needs a value");
		} else if (arg === "--version") {
			version = rawArgs[++i];
			if (version === undefined) throw new Error("--version needs a value");
		} else if (arg === "--reason") {
			reason = rawArgs[++i];
			if (reason === undefined) throw new Error("--reason needs a value");
		} else if (arg === "--key") {
			keyPath = rawArgs[++i];
			if (keyPath === undefined) throw new Error("--key needs a path");
		} else if (arg === "--out") {
			outPath = rawArgs[++i];
			if (outPath === undefined) throw new Error("--out needs a path");
		} else {
			throw new Error(`unknown flag ${arg}`);
		}
	}
	if (!server || !version || !reason) {
		throw new Error(
			"revoke needs --server, --version, and --reason (and --key for the project maintainer key)",
		);
	}
	const revocation: TrustRevocation = signRevocation({
		server,
		version,
		reason,
		keyPath,
	});
	// Sanity: the revocation must verify against its own key before we emit it.
	const check = verifyRevocation(revocation, revocation.keyId);
	if (!check.ok) {
		throw new Error(`revocation failed self-check: ${check.reason}`);
	}
	const json = `${JSON.stringify(revocation, null, 2)}\n`;
	if (outPath) {
		const dest = resolve(outPath);
		writeFileSync(dest, json);
		console.log(`revocation written to ${dest}`);
	} else {
		console.log(json);
	}
	console.log(
		`next: open a PR adding revocations/${server}/${version}.json to ${INDEX_REPO}; CI validates the project-key signature`,
	);
	return 0;
}

async function cmdPublish(rawArgs: string[]): Promise<number> {
	let badgePath: string | undefined;
	let repo: string | undefined;
	for (let i = 0; i < rawArgs.length; i++) {
		const arg = rawArgs[i];
		if (arg === "--badge") {
			badgePath = rawArgs[++i];
			if (badgePath === undefined) throw new Error("--badge needs a file");
		} else if (arg === "--repo") {
			repo = rawArgs[++i];
			if (repo === undefined) throw new Error("--repo needs owner/repo");
		} else throw new Error(`unknown flag ${arg}`);
	}
	if (badgePath === undefined) {
		throw new Error("publish needs a badge file: sigil publish --badge <file>");
	}
	const result = await publishBadge(badgePath, repo ? { repo } : {});
	console.log(`badge submitted: ${result.prUrl}`);
	return 0;
}

async function main(): Promise<number> {
	const [, , command, ...rest] = process.argv;
	try {
		switch (command) {
			case "scan":
				return await cmdScan(rest);
			case "keygen":
				return cmdKeygen(rest);
			case "verify":
				return await cmdVerify(rest);
			case "publish":
				return await cmdPublish(rest);
			case "pin":
				return await cmdPin(rest);
			case "install":
				return await cmdInstall(rest);
			case "revoke":
				return cmdRevoke(rest);
			case "--help":
			case "-h":
			case undefined:
				printHelp();
				return 0;
			case "--version":
			case "-v":
				console.log(VERSION);
				return 0;
			default:
				console.error(`unknown command "${command}"`);
				printHelp();
				return 1;
		}
	} catch (error) {
		console.error(
			`sigil: ${error instanceof Error ? error.message : String(error)}`,
		);
		return 1;
	}
}

function isMainModule(): boolean {
	const entry = process.argv[1];
	if (!entry) return false;
	try {
		// npm installs bins as symlinks: argv[1] is the unresolved link path
		// (e.g. <pkg>/node_modules/.bin/sigil) while import.meta.url is the
		// real path. Compare realpaths so the CLI starts when invoked
		// through the installed symlink.
		return realpathSync(entry) === fileURLToPath(import.meta.url);
	} catch {
		return false;
	}
}

const isMain = isMainModule();
if (isMain) {
	main().then(
		(code) => process.exit(code),
		(error) => {
			console.error(
				`sigil: ${error instanceof Error ? error.message : String(error)}`,
			);
			process.exit(1);
		},
	);
}
