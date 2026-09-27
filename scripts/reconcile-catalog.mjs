#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, verify } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
  ID, SEMVER, PLATFORMS, ROLES, FIDELITIES,
  decodeBase64, publicKeyFromRaw, validateCatalogDocument,
} from "./validate-catalog.mjs";
import { checkReleaseSequence } from "./check-release-sequence.mjs";

const VALIDITY_MS = 365 * 86400000;
const KIND_BY_MANIFEST = { app: "kosmos-package" };
const CATEGORY_BY_KIND = { "kosmos-package": "apps", integration: "integrations" };
const PUBLISHER_NAMES = { kosmos: "Kosmos" };

function fail(message) {
  throw new Error(`reconcile: ${message}`);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function toIso(date) {
  return date.toISOString();
}

function indexPackageManifest(entry, label) {
  if (!isObject(entry) || !isObject(entry.manifest)) fail(`${label}: malformed package entry`);
  const manifest = entry.manifest;
  if (typeof manifest.id !== "string" || !ID.test(manifest.id)) fail(`${label}: invalid package id`);
  if (typeof manifest.version !== "string" || !SEMVER.test(manifest.version)) fail(`${manifest.id}: invalid package version`);
  return manifest;
}

// Verifies a published Package Index release directory before trusting any of
// its contents: the envelope payload must be the exact catalog bytes, the
// detached signatures document must match the envelope, every signature must
// verify under the release BOM public key, and the BOM must agree with the
// catalog sequence. Returns the verified packages keyed by manifest id.
export async function loadIndexRelease(dir) {
  const catalogBytes = await readFile(path.join(dir, "catalog.json")).catch(() => fail("index catalog.json is missing"));
  let catalog;
  try { catalog = JSON.parse(catalogBytes.toString("utf8")); } catch { fail("index catalog.json is not JSON"); }
  const envelope = JSON.parse(await readFile(path.join(dir, "catalog.envelope.json"), "utf8").catch(() => fail("index catalog.envelope.json is missing")));
  const signatures = JSON.parse(await readFile(path.join(dir, "catalog.signatures.json"), "utf8").catch(() => fail("index catalog.signatures.json is missing")));
  const bomBytes = await readFile(path.join(dir, "release-bom.v1.json")).catch(() => fail("index release-bom.v1.json is missing"));
  let bom;
  try { bom = JSON.parse(bomBytes.toString("utf8")); } catch { fail("index release-bom.v1.json is not JSON"); }

  if (!isObject(envelope) || typeof envelope.bytes !== "string") fail("index envelope is malformed");
  const envelopeBytes = decodeBase64(envelope.bytes, "index envelope bytes");
  if (Buffer.compare(envelopeBytes, catalogBytes) !== 0) fail("index envelope bytes do not match catalog.json");
  if (!isDeepStrictEqual(envelope.signatures, signatures)) fail("index envelope signatures do not match catalog.signatures.json");

  if (!isObject(catalog) || catalog.schema_version !== 1 || !Number.isSafeInteger(catalog.sequence) || catalog.sequence < 1 || !Array.isArray(catalog.packages)) {
    fail("index catalog is malformed");
  }
  if (!isObject(bom) || !isObject(bom.catalog)) fail("index release BOM is malformed");
  if (bom.catalog.sequence !== catalog.sequence) fail(`release BOM sequence ${bom.catalog.sequence} does not match index catalog ${catalog.sequence}`);
  if (typeof bom.catalog.signing_key_id !== "string" || !bom.catalog.signing_key_id) fail("release BOM signing_key_id is missing");
  const key = publicKeyFromRaw(bom.catalog.public_key);
  if (!Number.isSafeInteger(bom.catalog.store_sequence) || bom.catalog.store_sequence < 0) fail("release BOM store_sequence is invalid");
  const retired = bom.retired_package_ids ?? [];
  if (!Array.isArray(retired) || retired.some((id) => typeof id !== "string")) fail("release BOM retired_package_ids is invalid");

  const records = signatures?.signatures;
  if (!isObject(signatures) || signatures.schema_version !== 1 || !Array.isArray(records) || records.length === 0) {
    fail("index signatures document is malformed");
  }
  for (const record of records) {
    if (!isObject(record) || record.key_id !== bom.catalog.signing_key_id || record.algorithm !== "ed25519") {
      fail("index catalog has an unexpected signing key");
    }
    const signature = decodeBase64(record.signature, "index signature");
    if (signature.length !== 64 || !verify(null, catalogBytes, key, signature)) fail("index catalog signature does not verify");
  }

  const packages = new Map();
  for (const entry of catalog.packages) {
    const manifest = indexPackageManifest(entry, "index catalog");
    if (packages.has(manifest.id)) fail(`duplicate index package id ${manifest.id}`);
    packages.set(manifest.id, { version: manifest.version, manifest });
  }
  if (packages.size === 0) fail("index catalog has no packages");

  return {
    sequence: catalog.sequence,
    catalog,
    bom,
    packages,
    retired: new Set(retired),
    catalogSha256: sha256(catalogBytes),
    bomSha256: sha256(bomBytes),
  };
}

function scaffoldListing(manifest, indexSequence) {
  const platforms = [...new Set((Array.isArray(manifest.targets) ? manifest.targets : [])
    .flatMap((target) => (isObject(target) && Array.isArray(target.os) ? target.os : []))
    .filter((platform) => PLATFORMS.has(platform)))];
  if (platforms.length === 0) fail(`${manifest.id}: cannot derive supported platforms for a new listing`);
  if (typeof manifest.name !== "string" || !manifest.name.trim()) fail(`${manifest.id}: manifest name is required for a new listing`);
  if (typeof manifest.publisher !== "string" || !manifest.publisher.trim()) fail(`${manifest.id}: manifest publisher is required for a new listing`);
  if (typeof manifest.description !== "string" || !manifest.description.trim()) {
    fail(`${manifest.id}: index catalog ${indexSequence} has no Store listing and the manifest has no description; add the listing manually`);
  }
  const kind = KIND_BY_MANIFEST[manifest.kind] ?? "integration";
  const dataCompatibility = [];
  for (const mapping of manifest.data?.mappings ?? []) {
    if (!isObject(mapping) || typeof mapping.type !== "string" || !ID.test(mapping.type) ||
        typeof mapping.versions !== "string" || !ROLES.has(mapping.direction) || !FIDELITIES.has(mapping.fidelity)) {
      fail(`${manifest.id}: manifest data mapping cannot be reconciled into a Store listing`);
    }
    dataCompatibility.push({ type: mapping.type, versions: mapping.versions, roles: [mapping.direction], via: manifest.id, fidelity: mapping.fidelity });
  }
  return {
    id: manifest.id,
    kind,
    name: manifest.name,
    publisher: PUBLISHER_NAMES[manifest.publisher] ?? manifest.publisher,
    publisher_tier: manifest.publisher === "kosmos" ? "kosmos" : "community",
    description: manifest.description,
    categories: [CATEGORY_BY_KIND[kind]],
    availability: { platforms },
    data_compatibility: dataCompatibility,
    distribution: { package_id: manifest.id, version: manifest.version },
    connects_to: null,
    icon_url: null,
    screenshots: [],
  };
}

// Versions are SEMVER-shaped; precedence follows semver 2.0.0: numeric core
// triple, then prerelease identifiers where a release outranks its own
// prereleases and numeric identifiers rank below alphanumeric ones. Build
// metadata does not affect precedence.
export function compareSemver(a, b) {
  const parse = (version) => {
    const withoutBuild = version.split("+", 1)[0];
    const dash = withoutBuild.indexOf("-");
    return {
      core: (dash === -1 ? withoutBuild : withoutBuild.slice(0, dash)).split(".").map(Number),
      prerelease: dash === -1 ? null : withoutBuild.slice(dash + 1).split("."),
    };
  };
  const left = parse(a);
  const right = parse(b);
  for (let index = 0; index < 3; index += 1) {
    if (left.core[index] !== right.core[index]) return left.core[index] - right.core[index];
  }
  if (left.prerelease === null || right.prerelease === null) {
    if (left.prerelease === right.prerelease) return 0;
    return left.prerelease === null ? 1 : -1;
  }
  for (let index = 0; index < Math.max(left.prerelease.length, right.prerelease.length); index += 1) {
    const leftPart = left.prerelease[index];
    const rightPart = right.prerelease[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    const leftNumeric = /^\d+$/.test(leftPart);
    const rightNumeric = /^\d+$/.test(rightPart);
    if (leftNumeric && rightNumeric) {
      const diff = Number(leftPart) - Number(rightPart);
      if (diff !== 0) return diff;
    } else if (leftNumeric !== rightNumeric) {
      return leftNumeric ? -1 : 1;
    } else if (leftPart !== rightPart) {
      return leftPart < rightPart ? -1 : 1;
    }
  }
  return 0;
}

// Aligns a Store catalog document with a verified index release: package
// listings track index versions, newly published packages get scaffolded
// listings, and a changed catalog advances the sequence past the latest
// published Store release. Returns the next catalog (null when already in
// sync) plus the change summary. Fails closed: a Store package listing that
// is absent from or retired in the index release stops the reconcile.
export function reconcileCatalog(catalog, index, options = {}) {
  validateCatalogDocument(catalog);
  const next = structuredClone(catalog);
  const updated = [];
  const added = [];
  const seen = new Set();
  for (const listing of next.listings) {
    const packageId = listing.distribution?.package_id;
    if (typeof packageId !== "string") continue;
    seen.add(packageId);
    const entry = index.packages.get(packageId);
    if (!entry) {
      if (index.retired.has(packageId)) {
        fail(`${listing.id}: ${packageId} is retired in Package Index catalog ${index.sequence}; deprecate it with replacement_id or remove the listing`);
      }
      fail(`${listing.id}: ${packageId} is absent from Package Index catalog ${index.sequence}`);
    }
    if (listing.distribution.version !== entry.version) {
      if (compareSemver(entry.version, listing.distribution.version) < 0) {
        fail(`${listing.id}: Package Index catalog ${index.sequence} pins ${packageId} at ${entry.version}, below the advertised ${listing.distribution.version}; refusing to downgrade a Store listing`);
      }
      updated.push({ id: listing.id, package_id: packageId, from: listing.distribution.version, to: entry.version });
      listing.distribution.version = entry.version;
    }
  }
  for (const [packageId, entry] of index.packages) {
    if (seen.has(packageId)) continue;
    next.listings.push(scaffoldListing(entry.manifest, index.sequence));
    added.push(packageId);
  }
  if (updated.length === 0 && added.length === 0) return { catalog: null, updated, added };

  const latest = options.latestSequence ?? 0;
  if (options.sequence !== undefined && options.sequence < catalog.sequence) {
    fail(`sequence ${options.sequence} is below the committed catalog sequence ${catalog.sequence}`);
  }
  next.sequence = options.sequence ?? (catalog.sequence > latest ? catalog.sequence : latest + 1);
  checkReleaseSequence(next.sequence, latest);
  const issued = options.issuedAt ?? new Date();
  next.issued_at = toIso(issued);
  next.expires_at = toIso(options.expiresAt ?? new Date(issued.getTime() + VALIDITY_MS));
  validateCatalogDocument(next);
  return { catalog: next, updated, added };
}

export function buildFixture(index) {
  return {
    store_sequence: index.bom.catalog.store_sequence,
    package_index_sequence: index.sequence,
    package_index_catalog_sha256: index.catalogSha256,
    package_index_release_bom_sha256: index.bomSha256,
    packages: Object.fromEntries([...index.packages].map(([id, entry]) => [id, entry.version])),
  };
}

// Canonical catalog formatting: containers holding only primitives (or arrays
// of primitives) render inline, everything else expands with two-space indent.
function isInlineNode(value) {
  if (value === null || typeof value !== "object") return true;
  const values = Array.isArray(value) ? value : Object.values(value);
  return values.every((item) => item === null || typeof item !== "object" ||
    (Array.isArray(item) ? item : Object.values(item)).every((leaf) => leaf === null || typeof leaf !== "object"));
}

function renderInline(value) {
  if (Array.isArray(value)) return value.length ? `[${value.map(renderInline).join(", ")}]` : "[]";
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value);
    return entries.length ? `{ ${entries.map(([key, item]) => `${JSON.stringify(key)}: ${renderInline(item)}`).join(", ")} }` : "{}";
  }
  return JSON.stringify(value);
}

export function formatCatalogDocument(value, indent = 0) {
  if (isInlineNode(value)) return renderInline(value);
  const pad = "  ".repeat(indent);
  const childPad = "  ".repeat(indent + 1);
  if (Array.isArray(value)) {
    return `[\n${value.map((item) => childPad + formatCatalogDocument(item, indent + 1)).join(",\n")}\n${pad}]`;
  }
  return `{\n${Object.entries(value).map(([key, item]) => `${childPad}${JSON.stringify(key)}: ${formatCatalogDocument(item, indent + 1)}`).join(",\n")}\n${pad}}`;
}

export function formatCatalog(document) {
  return `${formatCatalogDocument(document)}\n`;
}

function stripValidity(document) {
  const { issued_at, expires_at, ...content } = document;
  return content;
}

// The fixture records the last reconciled Package Index release: its sequence
// and the SHA-256 of the verified index catalog and release BOM bytes.
// Reconciling an older index release would rewind pinned versions and the
// recorded index sequence, and an equal sequence whose catalog or release-BOM
// bytes differ means the published release was regenerated — all fail closed.
// A byte-identical replay of the last reconciled release, or any newer index
// sequence, proceeds. An existing but corrupt fixture also fails closed rather
// than silently disabling the guard; only a missing file or an empty
// bootstrap record skips the check.
function assertIndexReleaseProgress(index, fixtureText) {
  if (fixtureText === null) return;
  let fixture;
  try { fixture = JSON.parse(fixtureText); } catch { fail("reconcile fixture is not valid JSON"); }
  if (!isObject(fixture)) fail("reconcile fixture is malformed");
  if (fixture.package_index_sequence === undefined) return;
  if (!Number.isSafeInteger(fixture.package_index_sequence)) fail("reconcile fixture package_index_sequence is malformed");
  const lastSequence = fixture.package_index_sequence;
  if (index.sequence < lastSequence) {
    fail(`index catalog ${index.sequence} is older than last reconciled index catalog ${lastSequence}; refusing to downgrade Store listings`);
  }
  if (index.sequence === lastSequence) {
    if (fixture.package_index_catalog_sha256 !== index.catalogSha256) {
      fail(`index catalog ${index.sequence} bytes do not match the last reconciled release; refusing to reconcile a regenerated index release`);
    }
    if (fixture.package_index_release_bom_sha256 !== index.bomSha256) {
      fail(`index release BOM at catalog ${index.sequence} does not match the last reconciled release; refusing to reconcile a regenerated index release`);
    }
  }
}

// Reconciles catalog.json and the fixture against a downloaded index release.
// With check=true nothing is written and the result only reports drift. When
// baselinePath names a previous candidate that differs only in the validity
// window, its bytes are reused verbatim so repeated reconciles of the same
// index release stay byte-identical instead of restamping issued_at.
export async function reconcileFiles({ indexDir, catalogPath, fixturePath, baselinePath, sequence, latestSequence = 0, issuedAt, expiresAt, check = false }) {
  const index = await loadIndexRelease(indexDir);
  const catalogBytes = await readFile(catalogPath);
  const catalog = JSON.parse(catalogBytes.toString("utf8"));
  const existingFixture = await readFile(fixturePath, "utf8").catch(() => null);
  assertIndexReleaseProgress(index, existingFixture);
  const result = reconcileCatalog(catalog, index, { sequence, latestSequence, issuedAt, expiresAt });
  let catalogText = result.catalog ? formatCatalog(result.catalog) : catalogBytes.toString("utf8");
  if (result.catalog && baselinePath) {
    const baselineText = await readFile(baselinePath, "utf8").catch(() => null);
    if (baselineText !== null) {
      try {
        if (isDeepStrictEqual(stripValidity(result.catalog), stripValidity(JSON.parse(baselineText)))) catalogText = baselineText;
      } catch { /* an unparseable baseline is ignored */ }
    }
  }
  const fixtureText = `${JSON.stringify(buildFixture(index), null, 2)}\n`;
  const catalogChanged = catalogText !== catalogBytes.toString("utf8");
  const fixtureChanged = fixtureText !== existingFixture?.replace(/\r\n/g, "\n");
  if (!check) {
    if (catalogChanged) await writeFile(catalogPath, catalogText);
    if (fixtureChanged) await writeFile(fixturePath, fixtureText);
  }
  return {
    indexSequence: index.sequence,
    sequence: (result.catalog ?? catalog).sequence,
    updated: result.updated,
    added: result.added,
    catalogChanged,
    fixtureChanged,
    wrote: !check && (catalogChanged || fixtureChanged),
  };
}

function parseArgs(argv) {
  const args = { check: false, json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--check" || arg === "--json") args[arg.slice(2)] = true;
    else if (arg.startsWith("--")) {
      const key = arg.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
      const value = argv[++index];
      if (value === undefined || value.startsWith("--")) fail(`missing value for ${arg}`);
      args[key] = value;
    } else fail(`unexpected argument ${arg}`);
  }
  return args;
}

function optionalDate(value, label) {
  if (value === undefined) return undefined;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) fail(`${label} must be an ISO timestamp`);
  return parsed;
}

function optionalSequence(value, label) {
  if (value === undefined || value === "") return undefined;
  if (!/^\d+$/.test(value)) fail(`${label} must be a non-negative integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) fail(`${label} is out of range`);
  return parsed;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.indexDir) fail("--index-dir is required");
  const summary = await reconcileFiles({
    indexDir: args.indexDir,
    catalogPath: args.catalog ?? fileURLToPath(new URL("../catalog.json", import.meta.url)),
    fixturePath: args.fixture ?? fileURLToPath(new URL("./fixtures/package-index-release.v1.json", import.meta.url)),
    baselinePath: args.baseline,
    sequence: optionalSequence(args.sequence, "--sequence"),
    latestSequence: optionalSequence(args.latestSequence, "--latest-sequence") ??
      optionalSequence(process.env.STORE_LATEST_SEQUENCE, "STORE_LATEST_SEQUENCE") ?? 0,
    issuedAt: optionalDate(args.issuedAt, "--issued-at"),
    expiresAt: optionalDate(args.expiresAt, "--expires-at"),
    check: args.check,
  });
  if (args.json) {
    console.log(JSON.stringify(summary));
  } else {
    const inSync = !summary.catalogChanged && !summary.fixtureChanged;
    const verb = inSync ? "already in sync" : args.check ? "would change" : "updated";
    console.log(`Package Index catalog ${summary.indexSequence}: Store sequence ${summary.sequence}, ${verb}.`);
    for (const change of summary.updated) console.log(`  ${change.package_id}: ${change.from} -> ${change.to}`);
    for (const id of summary.added) console.log(`  ${id}: new listing scaffolded`);
    if (summary.fixtureChanged) console.log("  fixture package-index-release.v1.json: updated");
  }
  if (args.check && (summary.catalogChanged || summary.fixtureChanged)) {
    console.error("Store catalog has drifted from the published Package Index release.");
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
