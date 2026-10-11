/**
 * Static pass orchestration: manifest, source heuristics, tool extraction,
 * capability checks, description-poisoning scans, and dependency audit.
 *
 * `runtimeTools` carries the tools/list result from the behavioral pass when
 * it is available; capability and poisoning checks run against the runtime
 * list preferentially and fall back to source-extracted descriptors.
 */

import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { listSourceFiles } from "../resolve.js";
import { auditDependencies } from "./audit.js";
import { checkCapabilities, type ToolDescriptor } from "./capabilities.js";
import { extractToolsFromFile } from "./extract.js";
import { hitsToFindings, scanLines } from "./heuristics.js";
import { readManifest } from "./manifest.js";
import { scanDescription } from "./poisoning.js";
import type { StaticFinding, StaticReport } from "./types.js";

export interface RuntimeTool {
	readonly name: string;
	readonly description: string;
}

export interface StaticPassOptions {
	/** Skip the npm audit (faster, hermetic). */
	readonly skipAudit?: boolean;
	/** Tools from the live tools/list, when the behavioral pass already ran. */
	readonly runtimeTools?: readonly RuntimeTool[];
	/**
	 * True when the behavioral pass did not run, so no live tools/list is
	 * available. Used to flag scans where neither pass enumerated any tools.
	 */
	readonly noBehavioral?: boolean;
}

const MAX_FILES = 500;
const MAX_FILE_BYTES = 512 * 1024;

function readLinesCapped(path: string): string[] | null {
	try {
		const text = readFileSync(path, "utf8");
		if (text.length > MAX_FILE_BYTES) return null;
		return text.split("\n");
	} catch {
		return null;
	}
}

export async function runStaticPass(
	root: string,
	options: StaticPassOptions = {},
): Promise<StaticReport> {
	const started = Date.now();
	const manifest = readManifest(root);
	const findings: StaticFinding[] = [];

	const files = listSourceFiles(manifest.root).slice(0, MAX_FILES);

	for (const file of files) {
		const lines = readLinesCapped(file);
		if (lines === null) continue;
		const rel = relative(manifest.root, file);
		const hits = scanLines(rel, lines);
		if (hits.length > 0) {
			findings.push(...hitsToFindings(rel, lines, hits));
		}
	}

	// Tool descriptors: prefer the runtime list, fall back to extraction.
	let descriptors: ToolDescriptor[];
	let toolSource: StaticReport["toolSource"];
	if (options.runtimeTools && options.runtimeTools.length > 0) {
		descriptors = options.runtimeTools.map((t) => ({
			name: t.name,
			description: t.description,
			origin: "runtime" as const,
		}));
		toolSource = "runtime";
	} else {
		const seen = new Map<string, ToolDescriptor>();
		for (const file of files) {
			for (const d of extractToolsFromFile(file)) {
				if (!seen.has(d.name)) seen.set(d.name, d);
			}
		}
		descriptors = [...seen.values()];
		toolSource = descriptors.length > 0 ? "extracted" : "none";
	}

	// When neither pass enumerated a single tool, the capability and
	// poisoning checks examined nothing. A clean score at this point means
	// "no tool evidence examined", not "tools verified safe": flag it as a
	// major finding so the verdict lands at medium (verify further) instead
	// of low (trust). Source heuristics and the dependency audit still ran.
	if (toolSource === "none" && options.noBehavioral) {
		findings.push({
			id: "st-coverage-1",
			severity: "major",
			category: "static.capability",
			title:
				"No MCP tools could be enumerated: capability and poisoning checks examined zero tools",
			description:
				"The behavioral pass did not run (no live tools/list) and static tool extraction found no tool registrations in the source, so capability classification (including the lethal-trifecta check) and tool-description poisoning scans examined nothing. Source heuristics and the dependency audit still ran. Treat a clean score as 'no tool evidence examined', not 'tools verified safe'.",
			evidence: [
				"static.toolSource: none (no runtime tools/list, no extracted registrations)",
				"behavioral pass did not run",
			],
			recommendation:
				"Enumerate the tool surface another way (start the server and call tools/list) before trusting this verdict.",
		});
	}

	findings.push(...checkCapabilities(descriptors));
	for (const d of descriptors) {
		if (d.description) findings.push(...scanDescription(d.name, d.description));
	}

	const { summary, findings: depFindings } = options.skipAudit
		? {
				summary: {
					ran: false,
					critical: 0,
					high: 0,
					moderate: 0,
					low: 0,
					info: 0,
					note: "skipped by caller",
				},
				findings: [],
			}
		: await auditDependencies(manifest.root);
	findings.push(...depFindings);

	if (!manifest.hasMcpDependency) {
		findings.push({
			id: "st-man-1",
			severity: "info",
			category: "static.manifest",
			title: "No @modelcontextprotocol/sdk dependency declared",
			description:
				"package.json does not depend on the MCP SDK. The target may not be an MCP server, or it vendors the protocol another way.",
			evidence: ["package.json has no @modelcontextprotocol/* dependency"],
		});
	}

	return {
		root: manifest.root,
		packageName: manifest.name,
		packageVersion: manifest.version,
		toolSource,
		toolCount: descriptors.length,
		findings,
		dependencies: summary,
		durationMs: Date.now() - started,
	};
}

export { readManifest, type ServerManifest } from "./manifest.js";
export type { StaticFinding, StaticReport };
