#!/usr/bin/env node
import { readFile } from "node:fs/promises";

const strictEnvelope = process.argv.includes("--strict-envelope");
const catalogBytes = await readFile(new URL("../catalog.json", import.meta.url));
const catalog = JSON.parse(catalogBytes);
if (catalog.schema_version !== 1 || !Number.isSafeInteger(catalog.sequence) || catalog.sequence < 1) throw new Error("invalid schema_version or sequence");
const issued = Date.parse(catalog.issued_at);
const expires = Date.parse(catalog.expires_at);
if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires <= issued || expires - issued > 366 * 86400000) throw new Error("invalid catalog validity window");
if (!Array.isArray(catalog.listings) || catalog.listings.length === 0) throw new Error("listings must be non-empty");

const ids = new Set();
for (const listing of catalog.listings) {
  if (!listing || typeof listing.id !== "string" || ids.has(listing.id)) throw new Error("duplicate or invalid listing id");
  ids.add(listing.id);
  for (const field of ["kind", "name", "publisher", "description"]) if (typeof listing[field] !== "string" || !listing[field]) throw new Error(`${listing.id}: ${field} is required`);
  if (!Array.isArray(listing.categories) || listing.categories.length === 0 || !Array.isArray(listing.availability?.platforms) || listing.availability.platforms.length === 0) throw new Error(`${listing.id}: categories/platforms are required`);
  if (listing.icon_url !== null && !/^https:\/\//.test(listing.icon_url)) throw new Error(`${listing.id}: icon_url must be HTTPS or null`);
  if (!Array.isArray(listing.screenshots) || listing.screenshots.some((url) => typeof url !== "string" || !/^https:\/\//.test(url))) throw new Error(`${listing.id}: screenshots must be HTTPS`);
  const distribution = listing.distribution;
  if (!distribution || typeof distribution !== "object") throw new Error(`${listing.id}: distribution is required`);
  if (listing.kind === "external-app") {
    if (typeof distribution.official_url !== "string" || !/^https:\/\//.test(distribution.official_url)) throw new Error(`${listing.id}: external app official_url is required`);
  } else if (typeof distribution.package_id !== "string" || typeof distribution.version !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(distribution.version)) {
    throw new Error(`${listing.id}: package distribution requires package_id and semver version`);
  }
}

const envelope = JSON.parse(await readFile(new URL("../catalog.envelope.json", import.meta.url), "utf8"));
if (typeof envelope.bytes !== "string" || !envelope.signatures || envelope.signatures.schema_version !== 1 || !Array.isArray(envelope.signatures.signatures) || envelope.signatures.signatures.length === 0) throw new Error("invalid committed envelope shape");
const envelopeBytes = Buffer.from(envelope.bytes, "base64");
let envelopeCatalog;
try { envelopeCatalog = JSON.parse(envelopeBytes); } catch { throw new Error("envelope bytes are not JSON"); }
if (envelopeCatalog.schema_version !== 1 || !Number.isSafeInteger(envelopeCatalog.sequence)) throw new Error("envelope payload is not a catalog");
if (strictEnvelope && Buffer.compare(envelopeBytes, catalogBytes) !== 0) throw new Error("committed envelope bytes do not match catalog.json");
if (!strictEnvelope && Buffer.compare(envelopeBytes, catalogBytes) !== 0) console.warn("warning: committed envelope is a previous signed catalog; publication must regenerate it");
for (const signature of envelope.signatures.signatures) {
  if (typeof signature.key_id !== "string" || signature.algorithm !== "ed25519" || typeof signature.signature !== "string") throw new Error("invalid signature record");
}
console.log(`Validated catalog sequence ${catalog.sequence} with ${catalog.listings.length} listings.`);
