import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { validateCatalog } from "./validate-catalog.mjs";

const catalog = JSON.parse(await readFile(new URL("../catalog.json", import.meta.url), "utf8"));
const envelope = JSON.parse(await readFile(new URL("../catalog.envelope.json", import.meta.url), "utf8"));

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
  value.bytes = Buffer.from(JSON.stringify({ schema_version: 1, sequence: catalog.sequence })).toString("base64");
  assert.throws(() => validateCatalog(catalog, value), /signature does not verify/);
});
