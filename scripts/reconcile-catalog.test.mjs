import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  buildFixture, formatCatalog, loadIndexRelease, reconcileCatalog, reconcileFiles,
} from "./reconcile-catalog.mjs";
import { validateCatalogDocument } from "./validate-catalog.mjs";

const realCatalogBytes = await readFile(new URL("../catalog.json", import.meta.url));

function indexPackage(id, version, { kind = "app", name, description = `${id} package`, os = ["windows"], mappings = [] } = {}) {
  return {
    archive_url: `https://example.test/releases/${id}-${version}.kspkg`,
    sha256: "ab".repeat(32),
    size: 1,
    manifest: {
      schema_version: 2,
      id,
      kind,
      name: name ?? id,
      publisher: "kosmos",
      version,
      description,
      engine_api: ">=1.0.0",
      entrypoint: "worker.exe",
      targets: [{ os, runtime: "worker" }],
      data: { access: [], defines: [], mappings },
    },
  };
}

function packageListing(id, version, extra = {}) {
  return {
    id,
    kind: "kosmos-package",
    name: id,
    publisher: "Kosmos",
    publisher_tier: "kosmos",
    description: `${id} listing`,
    categories: ["apps"],
    availability: { platforms: ["windows"] },
    data_compatibility: [],
    distribution: { package_id: id, version },
    connects_to: null,
    icon_url: null,
    screenshots: [],
    ...extra,
  };
}

function storeCatalog(listings, sequence = 5) {
  return {
    schema_version: 1,
    sequence,
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2026-12-31T00:00:00Z",
    listings,
  };
}

async function writeIndexRelease(t, packages, { sequence = 30, storeSequence = 1, retired = [] } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), "index-release-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const catalog = {
    schema_version: 1,
    sequence,
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    packages,
  };
  const catalogBytes = Buffer.from(JSON.stringify(catalog));
  const signatures = {
    schema_version: 1,
    signatures: [{
      key_id: "test-release",
      algorithm: "ed25519",
      signature: sign(null, catalogBytes, privateKey).toString("base64"),
    }],
  };
  const envelope = { bytes: catalogBytes.toString("base64"), signatures };
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const bom = {
    schema_version: 1,
    catalog: {
      sequence,
      previous_sequence: sequence - 1,
      store_sequence: storeSequence,
      channel: "production",
      signing_key_id: "test-release",
      public_key: publicDer.subarray(-32).toString("base64"),
    },
    retired_package_ids: retired,
  };
  await writeFile(path.join(dir, "catalog.json"), catalogBytes);
  await writeFile(path.join(dir, "catalog.envelope.json"), JSON.stringify(envelope));
  await writeFile(path.join(dir, "catalog.signatures.json"), JSON.stringify(signatures));
  await writeFile(path.join(dir, "release-bom.v1.json"), JSON.stringify(bom));
  return { dir, catalogBytes };
}

async function writeStore(t, catalog) {
  const dir = await mkdtemp(path.join(tmpdir(), "store-candidate-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const catalogPath = path.join(dir, "catalog.json");
  const fixturePath = path.join(dir, "package-index-release.v1.json");
  await writeFile(catalogPath, formatCatalog(catalog));
  await writeFile(fixturePath, "{}\n");
  return { dir, catalogPath, fixturePath };
}

test("index release must carry a valid signature over the catalog bytes", async (t) => {
  const { dir } = await writeIndexRelease(t, [indexPackage("com.example.one", "1.0.0")]);
  const tampered = JSON.parse(await readFile(path.join(dir, "catalog.signatures.json"), "utf8"));
  tampered.signatures[0].signature = Buffer.alloc(64).toString("base64");
  await writeFile(path.join(dir, "catalog.signatures.json"), JSON.stringify(tampered));
  const envelope = JSON.parse(await readFile(path.join(dir, "catalog.envelope.json"), "utf8"));
  envelope.signatures = tampered;
  await writeFile(path.join(dir, "catalog.envelope.json"), JSON.stringify(envelope));
  await assert.rejects(() => loadIndexRelease(dir), /signature does not verify/);
});

test("index release rejects envelope/signatures and BOM/catalog mismatches", async (t) => {
  const { dir } = await writeIndexRelease(t, [indexPackage("com.example.one", "1.0.0")]);
  const bom = JSON.parse(await readFile(path.join(dir, "release-bom.v1.json"), "utf8"));
  bom.catalog.sequence += 1;
  await writeFile(path.join(dir, "release-bom.v1.json"), JSON.stringify(bom));
  await assert.rejects(() => loadIndexRelease(dir), /does not match index catalog/);

  const good = await writeIndexRelease(t, [indexPackage("com.example.two", "2.0.0")]);
  const envelope = JSON.parse(await readFile(path.join(good.dir, "catalog.envelope.json"), "utf8"));
  envelope.signatures = { schema_version: 1, signatures: [] };
  await writeFile(path.join(good.dir, "catalog.envelope.json"), JSON.stringify(envelope));
  await assert.rejects(() => loadIndexRelease(good.dir), /signatures do not match/);
});

test("reconcile syncs versions, advances the sequence, and rewrites the fixture", async (t) => {
  const { dir } = await writeIndexRelease(t, [
    indexPackage("com.example.one", "1.2.0"),
    indexPackage("com.example.two", "2.0.0"),
  ], { sequence: 30, storeSequence: 7 });
  const store = await writeStore(t, storeCatalog([
    packageListing("com.example.one", "1.0.0"),
    packageListing("com.example.two", "2.0.0"),
  ], 5));
  const summary = await reconcileFiles({
    indexDir: dir,
    catalogPath: store.catalogPath,
    fixturePath: store.fixturePath,
    latestSequence: 5,
    issuedAt: new Date("2026-02-01T00:00:00Z"),
  });
  assert.deepEqual(summary.updated, [{ id: "com.example.one", package_id: "com.example.one", from: "1.0.0", to: "1.2.0" }]);
  assert.equal(summary.added.length, 0);
  assert.equal(summary.catalogChanged, true);
  assert.equal(summary.fixtureChanged, true);
  const written = JSON.parse(await readFile(store.catalogPath, "utf8"));
  assert.equal(written.sequence, 6);
  assert.equal(written.listings[0].distribution.version, "1.2.0");
  validateCatalogDocument(written);
  const fixture = JSON.parse(await readFile(store.fixturePath, "utf8"));
  assert.equal(fixture.package_index_sequence, 30);
  assert.equal(fixture.store_sequence, 7);
  assert.equal(fixture.packages["com.example.one"], "1.2.0");
});

test("reconcile scaffolds a listing for a newly published index package", async (t) => {
  const { dir } = await writeIndexRelease(t, [
    indexPackage("com.example.one", "1.0.0"),
    indexPackage("com.example.new", "0.1.0", {
      kind: "source",
      name: "New Source",
      mappings: [{ type: "com.example.archive", versions: "^1.0.0", direction: "import", fidelity: "lossless" }],
    }),
  ]);
  const store = await writeStore(t, storeCatalog([packageListing("com.example.one", "1.0.0")], 5));
  const summary = await reconcileFiles({
    indexDir: dir,
    catalogPath: store.catalogPath,
    fixturePath: store.fixturePath,
    latestSequence: 5,
    issuedAt: new Date("2026-02-01T00:00:00Z"),
  });
  assert.deepEqual(summary.added, ["com.example.new"]);
  const written = JSON.parse(await readFile(store.catalogPath, "utf8"));
  const listing = written.listings.find((item) => item.id === "com.example.new");
  assert.equal(listing.kind, "integration");
  assert.equal(listing.distribution.version, "0.1.0");
  assert.deepEqual(listing.data_compatibility, [
    { type: "com.example.archive", versions: "^1.0.0", roles: ["import"], via: "com.example.new", fidelity: "lossless" },
  ]);
  validateCatalogDocument(written);
});

test("reconcile keeps an unpublished candidate sequence instead of skipping it", async (t) => {
  const { dir } = await writeIndexRelease(t, [indexPackage("com.example.one", "1.2.0")]);
  const store = storeCatalog([packageListing("com.example.one", "1.0.0")], 19);
  const index = await loadIndexRelease(dir);
  const result = reconcileCatalog(store, index, { latestSequence: 18, issuedAt: new Date("2026-02-01T00:00:00Z") });
  assert.equal(result.catalog.sequence, 19);
});

test("reconcile fails closed when a Store package is absent from the index", async (t) => {
  const { dir } = await writeIndexRelease(t, [indexPackage("com.example.one", "1.0.0")]);
  const index = await loadIndexRelease(dir);
  const store = storeCatalog([
    packageListing("com.example.one", "1.0.0"),
    packageListing("com.example.gone", "3.0.0"),
  ]);
  assert.throws(() => reconcileCatalog(store, index, { latestSequence: 5 }), /absent from Package Index catalog/);
});

test("reconcile fails closed when the index BOM retires a Store package", async (t) => {
  const { dir } = await writeIndexRelease(t, [indexPackage("com.example.one", "1.0.0")], { retired: ["com.example.gone"] });
  const index = await loadIndexRelease(dir);
  const store = storeCatalog([
    packageListing("com.example.one", "1.0.0"),
    packageListing("com.example.gone", "3.0.0"),
  ]);
  assert.throws(() => reconcileCatalog(store, index, { latestSequence: 5 }), /is retired in Package Index catalog/);
});

test("reconcile fails when a scaffolded listing cannot be derived", async (t) => {
  const { dir } = await writeIndexRelease(t, [
    indexPackage("com.example.one", "1.0.0"),
    indexPackage("com.example.bare", "0.1.0", { description: "" }),
  ]);
  const index = await loadIndexRelease(dir);
  const store = storeCatalog([packageListing("com.example.one", "1.0.0")]);
  assert.throws(() => reconcileCatalog(store, index, { latestSequence: 5 }), /add the listing manually/);
});

test("check mode reports drift without writing files", async (t) => {
  const { dir } = await writeIndexRelease(t, [indexPackage("com.example.one", "1.2.0")]);
  const store = await writeStore(t, storeCatalog([packageListing("com.example.one", "1.0.0")], 5));
  const before = await readFile(store.catalogPath, "utf8");
  const summary = await reconcileFiles({
    indexDir: dir,
    catalogPath: store.catalogPath,
    fixturePath: store.fixturePath,
    latestSequence: 5,
    issuedAt: new Date("2026-02-01T00:00:00Z"),
    check: true,
  });
  assert.equal(summary.catalogChanged, true);
  assert.equal(summary.wrote, false);
  assert.equal(await readFile(store.catalogPath, "utf8"), before);
});

test("reconcile is idempotent once the candidate matches the index", async (t) => {
  const { dir } = await writeIndexRelease(t, [indexPackage("com.example.one", "1.2.0")]);
  const store = await writeStore(t, storeCatalog([packageListing("com.example.one", "1.0.0")], 5));
  const options = { indexDir: dir, catalogPath: store.catalogPath, fixturePath: store.fixturePath, latestSequence: 5, issuedAt: new Date("2026-02-01T00:00:00Z") };
  await reconcileFiles(options);
  const second = await reconcileFiles({ ...options, check: true });
  assert.equal(second.catalogChanged, false);
  assert.equal(second.fixtureChanged, false);
});

test("reconcile reuses a prior candidate when only the validity window differs", async (t) => {
  const { dir } = await writeIndexRelease(t, [indexPackage("com.example.one", "1.2.0")]);
  const drifted = storeCatalog([packageListing("com.example.one", "1.0.0")], 5);
  const store = await writeStore(t, drifted);
  const options = { indexDir: dir, catalogPath: store.catalogPath, fixturePath: store.fixturePath, latestSequence: 5 };
  await reconcileFiles({ ...options, issuedAt: new Date("2026-02-01T00:00:00Z") });
  const first = await readFile(store.catalogPath, "utf8");
  const baselinePath = path.join(store.dir, "prior-catalog.json");
  await writeFile(baselinePath, first);
  await writeFile(store.catalogPath, formatCatalog(drifted));
  await reconcileFiles({ ...options, baselinePath, issuedAt: new Date("2026-03-01T00:00:00Z") });
  assert.equal(await readFile(store.catalogPath, "utf8"), first);
});

test("a baseline with different semantic content is not reused", async (t) => {
  const { dir } = await writeIndexRelease(t, [indexPackage("com.example.one", "1.2.0")]);
  const store = await writeStore(t, storeCatalog([packageListing("com.example.one", "1.0.0")], 5));
  const baselinePath = path.join(store.dir, "prior-catalog.json");
  await writeFile(baselinePath, formatCatalog(storeCatalog([packageListing("com.example.one", "1.2.0")], 7)));
  await reconcileFiles({
    indexDir: dir,
    catalogPath: store.catalogPath,
    fixturePath: store.fixturePath,
    baselinePath,
    latestSequence: 5,
    issuedAt: new Date("2026-03-01T00:00:00Z"),
  });
  const written = JSON.parse(await readFile(store.catalogPath, "utf8"));
  assert.equal(written.sequence, 6);
  assert.equal(written.issued_at, "2026-03-01T00:00:00.000Z");
});

test("catalog formatting reproduces the committed catalog bytes", () => {
  assert.equal(formatCatalog(JSON.parse(realCatalogBytes.toString("utf8"))), realCatalogBytes.toString("utf8"));
});

test("fixture records the verified index release hashes", async (t) => {
  const { dir, catalogBytes } = await writeIndexRelease(t, [indexPackage("com.example.one", "1.0.0")], { sequence: 30 });
  const index = await loadIndexRelease(dir);
  const fixture = buildFixture(index);
  const { createHash } = await import("node:crypto");
  assert.equal(fixture.package_index_catalog_sha256, createHash("sha256").update(catalogBytes).digest("hex"));
  assert.equal(fixture.package_index_sequence, 30);
});
