import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
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

test("distribution versions follow the semver 2.0.0 grammar", () => {
  for (const version of ["1.0.0-alpha..1", "1.0.0-.", "1.0.0+meta..x", "01.2.3", "1.0.0-01", "1.0.0+..", "1.2"]) {
    const value = structuredClone(catalog);
    value.listings[0].distribution.version = version;
    assert.throws(() => validateCatalog(value, envelope), /semver/, version);
  }
  for (const version of ["1.2.3", "1.2.3-rc.1", "1.2.3+build.5", "1.2.3-rc.1+build.5"]) {
    const value = structuredClone(catalog);
    value.listings[0].distribution.version = version;
    validateCatalog(value, envelope);
  }
});

test("compatibility ranges follow the comparator grammar", () => {
  const listing = (value) => value.listings.find((item) => item.id === "ark-markdown-bridge").data_compatibility[0];
  for (const versions of ["=>1.0.0", "<>1.0.0", "==1.0.0", "1.2.x.3", "1.2.3.4.5", "v1.2.3junk", "1.0.0 - 2.0.0", "1.0.0 || 2.0.0"]) {
    const value = structuredClone(catalog);
    listing(value).versions = versions;
    assert.throws(() => validateCatalog(value, envelope), /compatibility/, versions);
  }
  for (const versions of ["*", "x", ">=1.0.0", ">= 1.0.0", "=1.2.3", "~1.2", "~>1.0.0", "^1.0.0", "~1.0.0-rc.1", "^2.0.0-beta.2", ">=1.0.0 <2.0.0", "1.2.x"]) {
    const value = structuredClone(catalog);
    listing(value).versions = versions;
    validateCatalog(value, envelope);
  }
});

test("dangling compatibility via references fail", () => {
  const value = structuredClone(catalog);
  value.listings.find((listing) => listing.id === "ark-markdown-bridge").data_compatibility[0].via = "ghost.app";
  assert.throws(() => validateCatalog(value, envelope), /via must reference an existing listing/);
});

test("connects_to self-references fail", () => {
  const value = structuredClone(catalog);
  value.listings[0].connects_to = value.listings[0].id;
  value.listings[0].distribution.connects_to = value.listings[0].id;
  assert.throws(() => validateCatalog(value, envelope), /connects_to/);
});

test("connects_to must be mirrored in distribution.connects_to", () => {
  const value = structuredClone(catalog);
  const listing = value.listings.find((item) => item.id === "com.kosmos.bigfrontend");
  delete listing.distribution.connects_to;
  assert.throws(() => validateCatalog(value, envelope), /connects_to/);
  const mirrored = structuredClone(catalog);
  const unconnected = mirrored.listings.find((item) => item.id === "com.kosmos.huawei-health");
  unconnected.distribution.connects_to = "external.obsidian";
  assert.throws(() => validateCatalog(mirrored, envelope), /connects_to/);
});

test("external apps cannot declare a package distribution", () => {
  const value = structuredClone(catalog);
  const external = value.listings.find((listing) => listing.kind === "external-app");
  external.distribution.package_id = "external.pkg";
  assert.throws(() => validateCatalog(value, envelope), /package_id/);
});

test("strict mode rejects stale reviewed bytes", () => {
  assert.throws(() => validateCatalog(catalog, envelope, {
    strictEnvelope: true,
    catalogBytes: Buffer.from(JSON.stringify(catalog, null, 2) + "\n"),
  }), /bytes do not match/);
});

test("Store candidate reconciles versions with the published Package Index catalog", () => {
  assert.ok(catalog.sequence >= packageIndexRelease.store_sequence);
  for (const [packageId, version] of Object.entries(packageIndexRelease.packages)) {
    const listing = catalog.listings.find((item) => item.id === packageId);
    assert.ok(listing, `${packageId} is advertised by the package-index release`);
    assert.equal(listing.distribution.version, version);
  }
});

test("candidate accepts a new sequence while preserving the historical signature", () => {
  const bytes = Buffer.from(JSON.stringify(catalog));
  assert.equal(validateCatalog(catalog, envelope, { candidate: true, catalogBytes: bytes }).sequence, catalog.sequence);
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

test("an expired catalog is rejected in candidate and plain modes", () => {
  const expired = structuredClone(catalog);
  expired.issued_at = "2020-01-01T00:00:00Z";
  expired.expires_at = "2020-07-01T00:00:00Z";
  assert.throws(() => validateCatalog(expired, envelope), /validity window has elapsed/);
  expired.sequence = catalog.sequence + 1;
  assert.throws(() => validateCatalog(expired, envelope, {
    candidate: true, catalogBytes: Buffer.from(JSON.stringify(expired)),
  }), /validity window has elapsed/);
});

test("CLI rejects unrecognized flags instead of silently weakening the gate", () => {
  const script = fileURLToPath(new URL("./validate-catalog.mjs", import.meta.url));
  const run = (args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  assert.equal(run(["--bogus"]).status, 1);
  assert.equal(run(["--strict"]).status, 1);
  assert.equal(run(["--candidate"]).status, 0);
});
