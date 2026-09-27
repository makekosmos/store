import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkReleaseSequence } from "./check-release-sequence.mjs";

test("release sequence must increase", () => {
  assert.equal(checkReleaseSequence(12, 11), true);
  assert.throws(() => checkReleaseSequence(12, 12), /not greater/);
  assert.throws(() => checkReleaseSequence(12, 13), /not greater/);
});

test("existing release or tag is immutable", () => {
  assert.throws(() => checkReleaseSequence(12, 11, { tagExists: true }), /already exists/);
});

test("sequence inputs are safe integers", () => {
  assert.throws(() => checkReleaseSequence(0, 0), /positive/);
  assert.throws(() => checkReleaseSequence(12, -1), /non-negative/);
  assert.throws(() => checkReleaseSequence(12, 1.5), /non-negative/);
});

test("CLI rejects a catalog whose sequence is not a JSON number", async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), "seq-gate-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(path.join(dir, "scripts"));
  const source = await readFile(new URL("./check-release-sequence.mjs", import.meta.url));
  const script = path.join(dir, "scripts", "check-release-sequence.mjs");
  await writeFile(script, source);
  for (const sequence of ["true", '"19"', "19.5"]) {
    await writeFile(path.join(dir, "catalog.json"), JSON.stringify({ sequence: JSON.parse(sequence) }));
    const run = spawnSync(process.execPath, [script], { encoding: "utf8" });
    assert.equal(run.status, 1, `sequence ${sequence} must not pass the release gate`);
    assert.match(run.stderr, /positive integer/);
  }
});
