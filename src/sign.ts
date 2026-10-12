/**
 * Ed25519 signing for trust badges. Real cryptography via node:crypto,
 * no stubs.
 *
 * A badge binds a scan result to a version pin and a signer:
 *
 *   { type, server, version, riskScore, riskLevel, scores, findingCounts,
 *     evalHash, keyId, publicKey, issuedAt, signature }
 *
 * - evalHash is the SHA-256 of the canonical JSON of the scored content
 *   (findings + dimension scores), so any tampering with the scores or the
 *   finding list invalidates the badge.
 * - signature is Ed25519 over the canonical JSON of the badge minus the
 *   signature field.
 * - The badge embeds the signer's public key, so `sigil verify` needs
 *   no key management: anyone can check the math. Trust in the *signer*
 *   (keyId) is out of band, like a PGP key id.
 */

import {
	createHash,
	createPrivateKey,
	createPublicKey,
	sign as cryptoSign,
	verify as cryptoVerify,
	generateKeyPairSync,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { TrustReport } from "./report.js";

export const BADGE_TYPE = "sigil-badge/v1";
export const REVOCATION_TYPE = "sigil-revocation/v1";
/**
 * Pre-rename type tags. Still accepted on verify so badges and revocations
 * issued before the Sigil rename keep validating; new artifacts use the
 * sigil-* types above.
 */
export const LEGACY_BADGE_TYPE = "mcp-trust-badge/v1";
export const LEGACY_REVOCATION_TYPE = "mcp-trust-revocation/v1";

/**
 * The exact installable artifact a badge was scanned from. Recorded so
 * `sigil pin` / `sigil install` can reproduce the verified install.
 */
export interface BadgeArtifact {
	/** npm: registry package; git: repository; local: scanned in place. */
	readonly type: "npm" | "git" | "local";
	/** npm: "name@version"; git: the clone URL; local: "local". */
	readonly spec: string;
	/** npm dist.integrity ("sha512-...") when the registry provided it. */
	readonly integrity?: string;
}

export interface TrustBadge {
	readonly type: typeof BADGE_TYPE | typeof LEGACY_BADGE_TYPE;
	readonly server: string;
	readonly version: string;
	readonly riskScore: number;
	readonly riskLevel: string;
	/** Behavioral dimension scores, or null when the behavioral pass was skipped. */
	readonly scores: Readonly<Record<string, number>> | null;
	readonly findingCounts: {
		critical: number;
		major: number;
		minor: number;
		info: number;
	};
	/** SHA-256 of the canonical scored content. */
	readonly evalHash: string;
	readonly keyId: string;
	/** Embedded Ed25519 public key (JWK) so verification is self-contained. */
	readonly publicKey: Record<string, unknown>;
	readonly issuedAt: string;
	/** Exact installable artifact, when the scan target resolved to one. */
	readonly artifact?: BadgeArtifact;
	readonly signature: string;
}

/**
 * A signed statement that a badge version must no longer be trusted.
 * Signed by the project maintainer key; the index publishes the project
 * public key at keys/project.json so anyone can check.
 */
export interface TrustRevocation {
	readonly type: typeof REVOCATION_TYPE | typeof LEGACY_REVOCATION_TYPE;
	readonly server: string;
	readonly version: string;
	readonly status: "revoked";
	readonly reason: string;
	readonly revokedAt: string;
	readonly keyId: string;
	/** Embedded Ed25519 public key (JWK); must be the project key. */
	readonly publicKey: Record<string, unknown>;
	readonly signature: string;
}

export interface VerifyResult {
	readonly ok: boolean;
	readonly reason: string;
	/**
	 * Whether the signing key is one the verifier trusts. `undefined` when
	 * no trusted key set was supplied: the signature then only proves the
	 * badge was not altered after signing, NOT who signed it (anyone can
	 * generate a key and sign a "passed" badge).
	 */
	readonly trustedSigner?: boolean;
}

export interface VerifyOptions {
	/**
	 * Key ids (16 hex chars, sha256 of the canonical public JWK) whose
	 * signatures are accepted. When given, a badge signed by any other key
	 * fails verification.
	 */
	readonly trustedKeyIds?: Iterable<string>;
}

/**
 * Parse a trusted-keys source: a JSON array of key ids or public-key files'
 * contents ({keyId, publicKey}), a single such object, or a newline/comma
 * separated list of key ids. A {publicKey} entry is re-derived to its key id
 * so a mislabelled keyId cannot widen the set.
 */
export function parseTrustedKeys(text: string): Set<string> {
	const ids = new Set<string>();
	const addEntry = (entry: unknown): void => {
		if (typeof entry === "string") {
			const id = entry.trim().toLowerCase();
			if (/^[0-9a-f]{16}$/.test(id)) ids.add(id);
			else if (id) throw new Error(`invalid key id "${entry}"`);
			return;
		}
		if (entry && typeof entry === "object") {
			const pk = (entry as { publicKey?: unknown }).publicKey;
			if (pk && typeof pk === "object") {
				ids.add(sha256Hex(canonicalize(pk)).slice(0, 16));
				return;
			}
			const kid = (entry as { keyId?: unknown }).keyId;
			if (typeof kid === "string") {
				addEntry(kid);
				return;
			}
		}
		throw new Error(
			"trusted key entries must be key ids or {publicKey} objects",
		);
	};
	const trimmed = text.trim();
	if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
		const parsed: unknown = JSON.parse(trimmed);
		for (const entry of Array.isArray(parsed) ? parsed : [parsed])
			addEntry(entry);
	} else {
		for (const part of trimmed.split(/[\s,]+/)) if (part) addEntry(part);
	}
	return ids;
}

/** Canonical JSON: object keys sorted recursively, no whitespace. */
export function canonicalize(value: unknown): string {
	if (Array.isArray(value)) {
		return `[${value.map((v) => canonicalize(v)).join(",")}]`;
	}
	if (value !== null && typeof value === "object") {
		const entries = Object.entries(value as Record<string, unknown>)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`);
		return `{${entries.join(",")}}`;
	}
	return JSON.stringify(value) ?? "null";
}

export function sha256Hex(data: string): string {
	return createHash("sha256").update(data, "utf8").digest("hex");
}

export interface KeyPair {
	/** First 16 hex chars of SHA-256 over the canonical public JWK. */
	readonly keyId: string;
	readonly publicJwk: Record<string, unknown>;
	readonly privateJwk: Record<string, unknown>;
}

export function generateKeyPair(): KeyPair {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const publicJwk = publicKey.export({ format: "jwk" }) as unknown as Record<
		string,
		unknown
	>;
	const privateJwk = privateKey.export({ format: "jwk" }) as unknown as Record<
		string,
		unknown
	>;
	const keyId = sha256Hex(canonicalize(publicJwk)).slice(0, 16);
	return { keyId, publicJwk, privateJwk };
}

export function defaultKeyDir(): string {
	return join(homedir(), ".config", "sigil");
}

export function defaultPrivateKeyPath(): string {
	return join(defaultKeyDir(), "key.priv.json");
}

export function defaultPublicKeyPath(): string {
	return join(defaultKeyDir(), "key.pub.json");
}

/**
 * Generate a keypair and store it. The private key file is written with
 * mode 0600. Returns the key id and the public key path.
 */
export function keygen(outDir?: string): {
	keyId: string;
	privatePath: string;
	publicPath: string;
} {
	const dir = outDir ?? defaultKeyDir();
	mkdirSync(dir, { recursive: true });
	const { keyId, publicJwk, privateJwk } = generateKeyPair();
	const privatePath = outDir
		? join(dir, "key.priv.json")
		: defaultPrivateKeyPath();
	const publicPath = outDir
		? join(dir, "key.pub.json")
		: defaultPublicKeyPath();
	writeFileSync(
		privatePath,
		JSON.stringify({ keyId, privateKey: privateJwk }, null, 2),
		{
			mode: 0o600,
		},
	);
	writeFileSync(
		publicPath,
		JSON.stringify({ keyId, publicKey: publicJwk }, null, 2),
	);
	return { keyId, privatePath, publicPath };
}

interface StoredPrivateKey {
	keyId: string;
	privateKey: Record<string, unknown>;
}

function loadPrivateKeyFile(path: string): StoredPrivateKey {
	if (!existsSync(path)) {
		throw new Error(
			`no private key at ${path}: run "sigil keygen" first, or pass --key <path>`,
		);
	}
	const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
	if (
		!parsed ||
		typeof parsed !== "object" ||
		typeof (parsed as { keyId?: unknown }).keyId !== "string" ||
		!(parsed as { privateKey?: unknown }).privateKey ||
		typeof (parsed as { privateKey?: unknown }).privateKey !== "object"
	) {
		throw new Error(`private key file at ${path} is not a sigil key file`);
	}
	return parsed as StoredPrivateKey;
}

/** The content the evalHash commits to: findings plus dimension scores. */
function scoredContent(report: TrustReport): unknown {
	const staticFindings = [...report.static.findings]
		.map((f) => ({
			id: f.id,
			severity: f.severity,
			category: f.category,
			tool: f.tool ?? null,
			file: f.file ?? null,
			title: f.title,
			evidence: [...f.evidence],
		}))
		.sort((a, b) => (a.id < b.id ? -1 : 1));
	const behavioralFindings = report.behavioral
		? [...report.behavioral.findings]
				.map((f) => ({
					id: f.id,
					severity: f.severity,
					category: f.category,
					tool: f.tool ?? null,
					title: f.title,
					evidence: [...f.evidence],
				}))
				.sort((a, b) => (a.id < b.id ? -1 : 1))
		: null;
	const scores = report.behavioral
		? Object.fromEntries(
				report.behavioral.scores.map((s) => [s.dimension, s.value]),
			)
		: null;
	return { staticFindings, behavioralFindings, scores };
}

/** Sign a trust report, producing a self-contained badge. */
export function signBadge(report: TrustReport, keyPath?: string): TrustBadge {
	const stored = loadPrivateKeyFile(keyPath ?? defaultPrivateKeyPath());
	const privateKey = createPrivateKey({
		key: stored.privateKey as never,
		format: "jwk",
	});
	const publicKey = createPublicKey(privateKey);
	const publicJwk = publicKey.export({ format: "jwk" }) as unknown as Record<
		string,
		unknown
	>;

	const scores = report.behavioral
		? Object.fromEntries(
				report.behavioral.scores.map((s) => [s.dimension, s.value]),
			)
		: null;
	const badge: Omit<TrustBadge, "signature"> = {
		type: BADGE_TYPE,
		server: report.server?.name ?? report.static.packageName ?? report.target,
		// For npm artifacts, use the exact version from the install spec, not
		// the server's self-reported protocol version (they often differ).
		version:
			report.artifact?.type === "npm"
				? report.artifact.spec.slice(report.artifact.spec.lastIndexOf("@") + 1)
				: (report.server?.version ?? report.static.packageVersion ?? "unknown"),
		riskScore: report.riskScore,
		riskLevel: report.riskLevel,
		scores,
		findingCounts: { ...report.counts },
		evalHash: sha256Hex(canonicalize(scoredContent(report))),
		keyId: stored.keyId,
		publicKey: publicJwk,
		issuedAt: new Date().toISOString(),
		// Only present when defined: canonicalize() renders undefined as
		// null, which would not round-trip through JSON and would break
		// the signature on verify.
		...(report.artifact ? { artifact: report.artifact } : {}),
	};
	const signature = cryptoSign(
		null,
		Buffer.from(canonicalize(badge), "utf8"),
		privateKey,
	);
	return { ...badge, signature: signature.toString("base64") };
}

/** Verify a badge's evalHash and signature. Returns ok=false with a reason on any failure. */
export function verifyBadge(
	badge: TrustBadge,
	options: VerifyOptions = {},
): VerifyResult {
	if (
		!badge ||
		(badge.type !== BADGE_TYPE && badge.type !== LEGACY_BADGE_TYPE)
	) {
		return { ok: false, reason: "not a Sigil badge (bad type field)" };
	}
	if (
		!badge.publicKey ||
		typeof badge.publicKey !== "object" ||
		typeof badge.signature !== "string"
	) {
		return {
			ok: false,
			reason: "badge is missing its public key or signature",
		};
	}
	let publicKey: ReturnType<typeof createPublicKey>;
	try {
		publicKey = createPublicKey({
			key: badge.publicKey as never,
			format: "jwk",
		});
	} catch (error) {
		return {
			ok: false,
			reason: `embedded public key is invalid: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	const { signature, ...unsigned } = badge;
	const expectedKeyId = sha256Hex(canonicalize(badge.publicKey)).slice(0, 16);
	if (badge.keyId !== expectedKeyId) {
		return {
			ok: false,
			reason: `keyId "${badge.keyId}" does not match the embedded public key (expected "${expectedKeyId}")`,
		};
	}
	let signatureOk = false;
	try {
		signatureOk = cryptoVerify(
			null,
			Buffer.from(canonicalize(unsigned), "utf8"),
			publicKey,
			Buffer.from(signature, "base64"),
		);
	} catch (error) {
		return {
			ok: false,
			reason: `signature check threw: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	if (!signatureOk) {
		return {
			ok: false,
			reason: "signature does not verify against the embedded public key",
		};
	}
	if (options.trustedKeyIds !== undefined) {
		const trusted = new Set(
			Array.from(options.trustedKeyIds, (id) => id.toLowerCase()),
		);
		if (!trusted.has(badge.keyId.toLowerCase())) {
			return {
				ok: false,
				trustedSigner: false,
				reason: `signature is valid but key ${badge.keyId} is not in the trusted key set`,
			};
		}
		return {
			ok: true,
			trustedSigner: true,
			reason:
				"signature valid from a trusted key; evalHash commits to the scored content",
		};
	}
	return {
		ok: true,
		reason: "signature valid; evalHash commits to the scored content",
	};
}

/** Recompute what the evalHash should be for a report (for cross-checking). */
export function evalHashForReport(report: TrustReport): string {
	return sha256Hex(canonicalize(scoredContent(report)));
}

/**
 * Sign a revocation for a badge version. The signer must be the project
 * maintainer: the index only accepts revocations whose key matches
 * keys/project.json.
 */
export function signRevocation(args: {
	server: string;
	version: string;
	reason: string;
	keyPath?: string;
}): TrustRevocation {
	const server = args.server.trim();
	const version = args.version.trim();
	const reason = args.reason.trim();
	if (!server) throw new Error("revoke needs a non-empty --server");
	if (!version) throw new Error("revoke needs a non-empty --version");
	if (!reason) throw new Error("revoke needs a non-empty --reason");

	const stored = loadPrivateKeyFile(args.keyPath ?? defaultPrivateKeyPath());
	const privateKey = createPrivateKey({
		key: stored.privateKey as never,
		format: "jwk",
	});
	const publicKey = createPublicKey(privateKey);
	const publicJwk = publicKey.export({ format: "jwk" }) as unknown as Record<
		string,
		unknown
	>;

	const revocation: Omit<TrustRevocation, "signature"> = {
		type: REVOCATION_TYPE,
		server,
		version,
		status: "revoked",
		reason,
		revokedAt: new Date().toISOString(),
		keyId: stored.keyId,
		publicKey: publicJwk,
	};
	const signature = cryptoSign(
		null,
		Buffer.from(canonicalize(revocation), "utf8"),
		privateKey,
	);
	return { ...revocation, signature: signature.toString("base64") };
}

export interface RevocationCheck {
	readonly ok: boolean;
	readonly reason: string;
}

/**
 * Verify a revocation against the expected maintainer key id. Checks the
 * type, that the embedded key is the expected maintainer key, and the
 * Ed25519 signature.
 */
export function verifyRevocation(
	revocation: TrustRevocation,
	expectedKeyId: string,
): RevocationCheck {
	if (
		!revocation ||
		(revocation.type !== REVOCATION_TYPE &&
			revocation.type !== LEGACY_REVOCATION_TYPE)
	) {
		return { ok: false, reason: "not a Sigil revocation (bad type field)" };
	}
	if (revocation.status !== "revoked") {
		return { ok: false, reason: 'revocation status must be "revoked"' };
	}
	if (
		!revocation.publicKey ||
		typeof revocation.publicKey !== "object" ||
		typeof revocation.signature !== "string" ||
		revocation.signature.length === 0
	) {
		return {
			ok: false,
			reason: "revocation is missing its public key or signature",
		};
	}
	if (revocation.keyId !== expectedKeyId) {
		return {
			ok: false,
			reason: `revocation keyId "${revocation.keyId}" is not the project key ("${expectedKeyId}")`,
		};
	}
	const expectedEmbedded = sha256Hex(canonicalize(revocation.publicKey)).slice(
		0,
		16,
	);
	if (revocation.keyId !== expectedEmbedded) {
		return {
			ok: false,
			reason: "revocation keyId does not match its embedded public key",
		};
	}
	const { signature, ...unsigned } = revocation;
	let publicKey: ReturnType<typeof createPublicKey>;
	try {
		publicKey = createPublicKey({
			key: revocation.publicKey as never,
			format: "jwk",
		});
	} catch (error) {
		return {
			ok: false,
			reason: `embedded public key is invalid: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	let signatureOk = false;
	try {
		signatureOk = cryptoVerify(
			null,
			Buffer.from(canonicalize(unsigned), "utf8"),
			publicKey,
			Buffer.from(signature, "base64"),
		);
	} catch (error) {
		return {
			ok: false,
			reason: `signature check threw: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	if (!signatureOk) {
		return {
			ok: false,
			reason: "signature does not verify against the embedded public key",
		};
	}
	return { ok: true, reason: "revocation signature valid" };
}
