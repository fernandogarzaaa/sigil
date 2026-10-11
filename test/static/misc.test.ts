import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { classifyTarget } from "../../src/resolve.js";
import { resetAuditIds, summarizeAudit } from "../../src/static/audit.js";
import { extractToolsFromText } from "../../src/static/extract.js";
import { runStaticPass } from "../../src/static/index.js";

describe("npm audit rollup", () => {
	it("turns critical/high counts into findings", () => {
		resetAuditIds();
		const { summary, findings } = summarizeAudit({
			metadata: {
				vulnerabilities: { critical: 2, high: 1, moderate: 0, low: 0, info: 0 },
			},
		});
		expect(summary.ran).toBe(true);
		expect(summary.critical).toBe(2);
		expect(
			findings.some(
				(f) => f.severity === "major" && f.title.includes("2 critical"),
			),
		).toBe(true);
		expect(
			findings.some(
				(f) => f.severity === "minor" && f.title.includes("1 high"),
			),
		).toBe(true);
	});

	it("degrades to an info finding when the audit produced nothing", () => {
		resetAuditIds();
		const { summary, findings } = summarizeAudit(null);
		expect(summary.ran).toBe(false);
		expect(findings).toHaveLength(1);
		expect(findings[0]!.severity).toBe("info");
	});
});

describe("tool extraction from source", () => {
	it("extracts server.tool() registrations with descriptions", () => {
		const found = extractToolsFromText(`
      server.tool("read_file", "Reads a file.", { path: {} }, async () => {});
      server.tool("get_status", async () => {});
    `);
		expect(found.map((t) => t.name).sort()).toEqual([
			"get_status",
			"read_file",
		]);
		expect(found.find((t) => t.name === "read_file")!.description).toBe(
			"Reads a file.",
		);
		expect(found.every((t) => t.origin === "extracted")).toBe(true);
	});

	it("dedupes repeated registrations", () => {
		const found = extractToolsFromText(
			'server.tool("a", "first");\nserver.tool("a", "second");',
		);
		expect(found).toHaveLength(1);
	});
});

describe("target classification", () => {
	const here = dirname(fileURLToPath(import.meta.url));
	const fixtureDir = join(here, "..", "fixtures", "fixture-server");

	it("classifies an existing directory as local", () => {
		expect(classifyTarget(fixtureDir)).toBe("local");
	});

	it("classifies npm specs", () => {
		expect(classifyTarget("express")).toBe("npm");
		expect(classifyTarget("express@4.18.2")).toBe("npm");
		expect(classifyTarget("@modelcontextprotocol/sdk@1.0.0")).toBe("npm");
	});

	it("classifies git URLs and owner/repo shorthand as git", () => {
		expect(classifyTarget("https://github.com/foo/bar.git")).toBe("git");
		expect(classifyTarget("git@github.com:foo/bar.git")).toBe("git");
		expect(classifyTarget("foo/bar")).toBe("git");
	});

	it("rejects garbage", () => {
		expect(() => classifyTarget("not a target !!!")).toThrow();
		expect(() => classifyTarget("")).toThrow();
	});
});

describe("no-tools-enumerated coverage finding", () => {
	async function emptyServerDir(): Promise<string> {
		const dir = await mkdtemp(join(tmpdir(), "sigil-no-tools-"));
		await writeFile(
			join(dir, "package.json"),
			JSON.stringify({ name: "empty-server", version: "0.0.0" }),
		);
		return dir;
	}

	it("flags major when neither pass enumerated any tools", async () => {
		const dir = await emptyServerDir();
		const report = await runStaticPass(dir, {
			noBehavioral: true,
			skipAudit: true,
		});
		expect(report.toolSource).toBe("none");
		expect(report.toolCount).toBe(0);
		const f = report.findings.find((x) => x.id === "st-coverage-1");
		expect(f).toBeDefined();
		expect(f!.severity).toBe("major");
	});

	it("stays silent when the behavioral pass supplied tools", async () => {
		const dir = await emptyServerDir();
		const report = await runStaticPass(dir, {
			noBehavioral: false,
			skipAudit: true,
			runtimeTools: [{ name: "t", description: "does things" }],
		});
		expect(report.findings.some((x) => x.id === "st-coverage-1")).toBe(false);
	});

	it("stays silent when extraction found tools", async () => {
		const dir = await mkdtemp(join(tmpdir(), "sigil-with-tools-"));
		await writeFile(
			join(dir, "package.json"),
			JSON.stringify({ name: "tool-server", version: "0.0.0" }),
		);
		await writeFile(
			join(dir, "server.js"),
			`server.tool("do-thing", "does a thing", async () => ({}));\n`,
		);
		const report = await runStaticPass(dir, {
			noBehavioral: true,
			skipAudit: true,
		});
		expect(report.toolSource).toBe("extracted");
		expect(report.findings.some((x) => x.id === "st-coverage-1")).toBe(false);
	});
});
