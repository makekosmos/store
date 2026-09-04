import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { validateCatalog } from "./validate-catalog.mjs";

const catalog = JSON.parse(await readFile(new URL("../catalog.json", import.meta.url), "utf8"));
const envelope = JSON.parse(await readFile(new URL("../catalog.envelope.json", import.meta.url), "utf8"));
const packageIndexRelease = JSON.parse(await readFile(new URL("./fixtures/package-index-release.v1.json", import.meta.url), "utf8"));

test("valid committed catalog and envelope", () => {
  assert.deepEqual(validateCatalog(catalog, envelope), { sequence: catalog.sequence, listings: catalog.listings.length });
});

test("duplicate IDs fail", () => {
  const value = structuredClone(catalog);
  value.listings.push(structuredClone(value.listings[0]));
  assert.throws(() => validateCatalog(value, envelope), /duplicate|invalid listing id/);
});

test("replacement cycles fail", () => {
  const value = structuredClone(catalog);
  value.listings[0].replacement_id = value.listings[1].id;
  value.listings[1].replacement_id = value.listings[0].id;
  assert.throws(() => validateCatalog(value, envelope), /replacement cycle/);
});

test("invalid sequence fails", () => {
  const value = structuredClone(catalog);
  value.sequence = 0;
  assert.throws(() => validateCatalog(value, envelope), /invalid sequence/);
});

test("wrong public-key signature fails", () => {
  const value = structuredClone(envelope);
  value.signatures.signatures[0].signature = Buffer.alloc(64).toString("base64");
  assert.throws(() => validateCatalog(catalog, value), /signature does not verify/);
});

test("altered envelope bytes fail signature verification", () => {
  const value = structuredClone(envelope);
  const altered = Buffer.from(value.bytes, "base64");
  altered[altered.length - 1] = 0x20;
  value.bytes = altered.toString("base64");
  assert.throws(() => validateCatalog(catalog, value), /signature does not verify/);
});

test("malformed URLs and compatibility ranges fail", () => {
  const value = structuredClone(catalog);
  value.listings[0].icon_url = "http://insecure.example/icon.png";
  assert.throws(() => validateCatalog(value, envelope), /icon_url/);
  const compatible = structuredClone(catalog);
  compatible.listings.find((listing) => listing.id === "ark-markdown-bridge").data_compatibility[0].versions = "not-a-range";
  assert.throws(() => validateCatalog(compatible, envelope), /compatibility/);
});

test("strict mode rejects stale reviewed bytes", () => {
  assert.throws(() => validateCatalog(catalog, envelope, {
    strictEnvelope: true,
    catalogBytes: Buffer.from(JSON.stringify(catalog, null, 2) + "\n"),
  }), /bytes do not match/);
});

test("Store candidate reconciles versions with the published Package Index catalog", () => {
  assert.equal(catalog.sequence, packageIndexRelease.store_sequence);
  for (const [packageId, version] of Object.entries(packageIndexRelease.packages)) {
    const listing = catalog.listings.find((item) => item.id === packageId);
    assert.ok(listing, `${packageId} is advertised by the package-index release`);
    assert.equal(listing.distribution.version, version);
  }
});

test("candidate accepts a new sequence while preserving the historical signature", () => {
  const bytes = Buffer.from(JSON.stringify(catalog));
  assert.equal(validateCatalog(catalog, envelope, { candidate: true, catalogBytes: bytes }).sequence, 14);
  assert.throws(() => validateCatalog(catalog, envelope, { strictEnvelope: true, catalogBytes: bytes }), /bytes do not match/);
});

test("candidate rejects same-sequence changes and rollback", () => {
  const previous = JSON.parse(Buffer.from(envelope.bytes, "base64"));
  for (const sequence of [previous.sequence, previous.sequence - 1]) {
    const candidate = { ...catalog, sequence };
    assert.throws(() => validateCatalog(candidate, envelope, {
      candidate: true, catalogBytes: Buffer.from(JSON.stringify(candidate)),
    }), /advance the signed sequence/);
  }
});

test("candidate accepts exact already-signed bytes and still rejects signature tampering", () => {
  const bytes = Buffer.from(envelope.bytes, "base64");
  const previous = JSON.parse(bytes);
  validateCatalog(previous, envelope, { candidate: true, catalogBytes: bytes });
  const invalid = structuredClone(envelope);
  invalid.signatures.signatures[0].signature = Buffer.alloc(64).toString("base64");
  assert.throws(() => validateCatalog(catalog, invalid, {
    candidate: true, catalogBytes: Buffer.from(JSON.stringify(catalog)),
  }), /signature does not verify/);
});
