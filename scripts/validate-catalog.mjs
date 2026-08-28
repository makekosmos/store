#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicKey, verify } from "node:crypto";

export const PRODUCTION_PUBLIC_KEY = "it14mzPjoqdgaHXdCDIjCoUgGXf/f5izJrGRUuk3o/A=";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const semver = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const https = /^https:\/\//;
const compatibilityRange = /^(?:[<>=~^*]|\d)/;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function validateReplacementChains(listings) {
  const byId = new Map(listings.map((listing) => [listing.id, listing]));
  const packageIds = new Set();
  for (const listing of listings) {
    const distribution = listing.distribution;
    if (listing.kind !== "external-app") {
      assert(typeof distribution.package_id === "string" && semver.test(distribution.version), `${listing.id}: package distribution requires package_id and semver version`);
      assert(!packageIds.has(distribution.package_id), `duplicate package identity: ${distribution.package_id}`);
      packageIds.add(distribution.package_id);
    }
    if (listing.connects_to !== null) {
      assert(typeof listing.connects_to === "string" && byId.has(listing.connects_to), `${listing.id}: connects_to must reference an existing listing`);
    }
    if (listing.replacement_id !== undefined) {
      assert(typeof listing.replacement_id === "string" && listing.replacement_id !== listing.id && byId.has(listing.replacement_id), `${listing.id}: invalid replacement_id`);
      const seen = new Set([listing.id]);
      let next = listing.replacement_id;
      while (next) {
        assert(!seen.has(next), `${listing.id}: replacement cycle`);
        seen.add(next);
        next = byId.get(next)?.replacement_id;
      }
    }
  }
}

export function validateCatalog(catalog, envelope, { strictEnvelope = false } = {}) {
  assert(catalog && catalog.schema_version === 1, "invalid schema_version");
  assert(Number.isSafeInteger(catalog.sequence) && catalog.sequence > 0, "invalid sequence");
  const issued = Date.parse(catalog.issued_at);
  const expires = Date.parse(catalog.expires_at);
  assert(Number.isFinite(issued) && Number.isFinite(expires) && expires > issued && expires - issued <= 366 * 86400000, "invalid catalog validity window");
  assert(Array.isArray(catalog.listings) && catalog.listings.length > 0, "listings must be non-empty");

  const ids = new Set();
  for (const listing of catalog.listings) {
    assert(listing && typeof listing.id === "string" && !ids.has(listing.id), "duplicate or invalid listing id");
    ids.add(listing.id);
    for (const field of ["kind", "name", "publisher", "description"]) assert(typeof listing[field] === "string" && listing[field], `${listing.id}: ${field} is required`);
    assert(Array.isArray(listing.categories) && listing.categories.length > 0, `${listing.id}: categories are required`);
    assert(Array.isArray(listing.availability?.platforms) && listing.availability.platforms.length > 0, `${listing.id}: platforms are required`);
    assert(listing.icon_url === null || (typeof listing.icon_url === "string" && https.test(listing.icon_url)), `${listing.id}: icon_url must be HTTPS or null`);
    assert(Array.isArray(listing.screenshots) && listing.screenshots.every((url) => typeof url === "string" && https.test(url)), `${listing.id}: screenshots must be HTTPS`);
    const distribution = listing.distribution;
    assert(distribution && typeof distribution === "object", `${listing.id}: distribution is required`);
    if (listing.kind === "external-app") {
      assert(typeof distribution.official_url === "string" && https.test(distribution.official_url), `${listing.id}: external app official_url is required`);
    } else {
      assert(typeof distribution.package_id === "string" && semver.test(distribution.version), `${listing.id}: package distribution requires package_id and semver version`);
    }
    for (const item of listing.data_compatibility ?? []) {
      assert(item && typeof item.type === "string" && typeof item.versions === "string" && compatibilityRange.test(item.versions), `${listing.id}: malformed data compatibility`);
    }
  }
  validateReplacementChains(catalog.listings);

  assert(envelope && typeof envelope.bytes === "string", "invalid committed envelope bytes");
  const envelopeBytes = Buffer.from(envelope.bytes, "base64");
  let envelopeCatalog;
  try { envelopeCatalog = JSON.parse(envelopeBytes); } catch { throw new Error("envelope bytes are not JSON"); }
  assert(envelopeCatalog.schema_version === 1 && Number.isSafeInteger(envelopeCatalog.sequence), "envelope payload is not a catalog");
  if (strictEnvelope) assert(Buffer.compare(envelopeBytes, Buffer.from(JSON.stringify(catalog, null, 2) + "\n")) === 0, "committed envelope bytes do not match catalog.json");
  assert(envelope.signatures?.schema_version === 1 && Array.isArray(envelope.signatures.signatures) && envelope.signatures.signatures.length > 0, "invalid signature records");
  const publicKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(PRODUCTION_PUBLIC_KEY, "base64")]), format: "der", type: "spki" });
  for (const signature of envelope.signatures.signatures) {
    assert(signature.key_id === "kosmos-store-2026" && signature.algorithm === "ed25519" && typeof signature.signature === "string", "invalid signature record");
    assert(verify(null, envelopeBytes, publicKey, Buffer.from(signature.signature, "base64")), "committed envelope signature does not verify");
  }
  return { sequence: catalog.sequence, listings: catalog.listings.length };
}

async function main() {
  const catalogPath = new URL("../catalog.json", import.meta.url);
  const envelopePath = new URL("../catalog.envelope.json", import.meta.url);
  const catalogBytes = await readFile(catalogPath);
  const catalog = JSON.parse(catalogBytes);
  const envelope = JSON.parse(await readFile(envelopePath, "utf8"));
  const result = validateCatalog(catalog, envelope, { strictEnvelope: process.argv.includes("--strict-envelope") });
  console.log(`Validated catalog sequence ${result.sequence} with ${result.listings} listings.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
