import assert from "node:assert/strict";
import test from "node:test";
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
