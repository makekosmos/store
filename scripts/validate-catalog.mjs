#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicKey, verify } from "node:crypto";

export const PRODUCTION_KEY_ID = "kosmos-store-2026";
export const PRODUCTION_PUBLIC_KEY = "it14mzPjoqdgaHXdCDIjCoUgGXf/f5izJrGRUuk3o/A=";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ID = /^[a-z0-9][a-z0-9._-]{1,127}$/;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const RANGE_TOKEN = /^(?:\*|(?:[<>=]{1,2}\s*)?[vV]?\d+(?:\.\d+|\.x|\.X)*(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?|[~^]\s*(?:[vV]?\d+(?:\.\d+|\.x|\.X)*))$/;
const HTTPS_URL = /^https:\/\/[^\s]+$/i;
const KINDS = new Set(["kosmos-package", "external-app", "integration"]);
const TIERS = new Set(["kosmos", "verified", "community"]);
const PLATFORMS = new Set(["windows", "macos", "linux", "ios", "android", "web"]);
const ROLES = new Set(["import", "export", "sync"]);
const FIDELITIES = new Set(["lossless", "lossy"]);

function isHttpsUrl(value) {
  if (typeof value !== "string" || !HTTPS_URL.test(value)) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && Boolean(url.hostname) && !url.username && !url.password;
  } catch {
    return false;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function decodeBase64(value, label) {
  assert(typeof value === "string" && value.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length % 4 === 0, `${label} must be base64`);
  const decoded = Buffer.from(value, "base64");
  assert(decoded.toString("base64") === value, `${label} must be canonical base64`);
  return decoded;
}

function validTimestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return NaN;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return NaN;
  const canonical = new Date(parsed).toISOString();
  return canonical === value || canonical.slice(0, 19) + "Z" === value ? parsed : NaN;
}

function validCompatibilityRange(value) {
  if (typeof value !== "string" || value.length > 128 || value.trim() !== value || value.includes("||")) return false;
  return value.split(/\s+/).every((token) => RANGE_TOKEN.test(token));
}

export function validateCatalogDocument(catalog) {
  assert(isObject(catalog), "catalog must be an object");
  assert(catalog.schema_version === 1, "invalid schema_version");
  assert(Number.isSafeInteger(catalog.sequence) && catalog.sequence > 0, "invalid sequence");
  const issued = validTimestamp(catalog.issued_at);
  const expires = validTimestamp(catalog.expires_at);
  assert(Number.isFinite(issued) && Number.isFinite(expires) && expires > issued && expires - issued <= 366 * 86400000, "invalid catalog validity window");
  assert(Array.isArray(catalog.listings) && catalog.listings.length > 0, "listings must be non-empty");

  const ids = new Set();
  const packageIds = new Set();
  for (const listing of catalog.listings) {
    assert(isObject(listing) && typeof listing.id === "string" && ID.test(listing.id) && !ids.has(listing.id), "duplicate or invalid listing id");
    ids.add(listing.id);
    assert(KINDS.has(listing.kind), `${listing.id}: invalid kind`);
    for (const field of ["name", "publisher", "description"]) assert(typeof listing[field] === "string" && listing[field].trim(), `${listing.id}: ${field} is required`);
    assert(typeof listing.publisher_tier === "string" && TIERS.has(listing.publisher_tier), `${listing.id}: invalid publisher_tier`);
    assert(Array.isArray(listing.categories) && listing.categories.length > 0 && new Set(listing.categories).size === listing.categories.length && listing.categories.every((x) => typeof x === "string" && /^[a-z0-9][a-z0-9-]{1,31}$/.test(x)), `${listing.id}: categories are invalid`);
    const platforms = listing.availability?.platforms;
    assert(Array.isArray(platforms) && platforms.length > 0 && new Set(platforms).size === platforms.length && platforms.every((x) => PLATFORMS.has(x)), `${listing.id}: platforms are invalid`);
    assert(Array.isArray(listing.screenshots) && listing.screenshots.length <= 12 && listing.screenshots.every(isHttpsUrl), `${listing.id}: screenshots must be HTTPS`);
    assert(listing.icon_url === null || isHttpsUrl(listing.icon_url), `${listing.id}: icon_url must be HTTPS or null`);
    assert(isObject(listing.distribution), `${listing.id}: distribution is required`);
    if (listing.kind === "external-app") {
      assert(isHttpsUrl(listing.distribution.official_url), `${listing.id}: external app official_url is required`);
    } else {
      assert(typeof listing.distribution.package_id === "string" && ID.test(listing.distribution.package_id) && SEMVER.test(listing.distribution.version), `${listing.id}: package distribution requires package_id and semver version`);
      assert(!packageIds.has(listing.distribution.package_id), `duplicate package identity: ${listing.distribution.package_id}`);
      packageIds.add(listing.distribution.package_id);
    }
    assert(listing.connects_to === null || (typeof listing.connects_to === "string" && ID.test(listing.connects_to)), `${listing.id}: connects_to must be a listing id or null`);
    if (listing.distribution.connects_to !== undefined) assert(listing.distribution.connects_to === listing.connects_to, `${listing.id}: distribution connects_to does not match listing`);
    assert(Array.isArray(listing.data_compatibility ?? []), `${listing.id}: data_compatibility must be an array`);
    for (const item of listing.data_compatibility ?? []) {
      assert(isObject(item) && typeof item.type === "string" && ID.test(item.type) && validCompatibilityRange(item.versions), `${listing.id}: malformed data compatibility`);
      assert(Array.isArray(item.roles) && item.roles.length > 0 && new Set(item.roles).size === item.roles.length && item.roles.every((role) => ROLES.has(role)), `${listing.id}: invalid compatibility roles`);
      assert(typeof item.via === "string" && ID.test(item.via), `${listing.id}: invalid compatibility via`);
      assert(FIDELITIES.has(item.fidelity), `${listing.id}: invalid compatibility fidelity`);
    }
    if (listing.deprecated !== undefined) assert(typeof listing.deprecated === "boolean", `${listing.id}: deprecated must be boolean`);
    if (listing.replacement_id !== undefined) assert(typeof listing.replacement_id === "string" && listing.replacement_id !== listing.id && ID.test(listing.replacement_id), `${listing.id}: invalid replacement_id`);
    if (listing.deprecated === true) assert(typeof listing.replacement_id === "string", `${listing.id}: deprecated listing requires replacement_id`);
  }

  const byId = new Map(catalog.listings.map((listing) => [listing.id, listing]));
  for (const listing of catalog.listings) {
    if (listing.connects_to !== null) assert(byId.has(listing.connects_to), `${listing.id}: connects_to must reference an existing listing`);
    if (listing.replacement_id !== undefined) {
      assert(byId.has(listing.replacement_id), `${listing.id}: replacement_id must reference an existing listing`);
      const seen = new Set([listing.id]);
      let next = listing.replacement_id;
      while (next !== undefined) {
        assert(!seen.has(next), `${listing.id}: replacement cycle`);
        seen.add(next);
        next = byId.get(next)?.replacement_id;
      }
    }
  }
  return { sequence: catalog.sequence, listings: catalog.listings.length };
}

function publicKeyFromRaw(raw) {
  const bytes = decodeBase64(raw, "public key");
  assert(bytes.length === 32, "Ed25519 public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, bytes]), format: "der", type: "spki" });
}

export function validateEnvelope(envelope, { publicKey = PRODUCTION_PUBLIC_KEY, catalogBytes, strictEnvelope = false } = {}) {
  assert(isObject(envelope) && typeof envelope.bytes === "string", "invalid committed envelope bytes");
  const envelopeBytes = decodeBase64(envelope.bytes, "envelope bytes");
  let envelopeCatalog;
  try { envelopeCatalog = JSON.parse(envelopeBytes.toString("utf8")); } catch { throw new Error("envelope bytes are not JSON"); }
  validateCatalogDocument(envelopeCatalog);
  if (strictEnvelope) {
    assert(catalogBytes, "strict envelope validation requires catalog bytes");
    assert(Buffer.compare(envelopeBytes, catalogBytes) === 0, "committed envelope bytes do not match catalog.json");
  }
  const signatures = envelope.signatures;
  assert(isObject(signatures) && signatures.schema_version === 1 && Array.isArray(signatures.signatures) && signatures.signatures.length > 0, "invalid signature records");
  const key = publicKeyFromRaw(publicKey);
  for (const record of signatures.signatures) {
    assert(isObject(record) && record.key_id === PRODUCTION_KEY_ID && record.algorithm === "ed25519", "invalid signature record");
    const signature = decodeBase64(record.signature, "signature");
    assert(signature.length === 64 && verify(null, envelopeBytes, key, signature), "committed envelope signature does not verify");
  }
  return { payload: envelopeCatalog, bytes: envelopeBytes };
}

export function validateCatalog(catalog, envelope, options = {}) {
  const result = validateCatalogDocument(catalog);
  assert(envelope, "committed envelope is required");
  const envelopeResult = validateEnvelope(envelope, options);
  if (options.strictEnvelope) assert(envelopeResult.payload.sequence === result.sequence, "catalog and envelope sequences differ");
  return result;
}

async function main() {
  const catalogPath = new URL("../catalog.json", import.meta.url);
  const envelopePath = new URL("../catalog.envelope.json", import.meta.url);
  const catalogBytes = await readFile(catalogPath);
  const catalog = JSON.parse(catalogBytes);
  const envelope = JSON.parse(await readFile(envelopePath, "utf8"));
  const result = validateCatalog(catalog, envelope, { strictEnvelope: process.argv.includes("--strict-envelope"), catalogBytes });
  console.log(`Validated catalog sequence ${result.sequence} with ${result.listings} listings.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
