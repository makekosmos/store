#!/usr/bin/env node
import { readFile } from "node:fs/promises";

export function checkReleaseSequence(current, latest = 0, { tagExists = false } = {}) {
  if (!Number.isSafeInteger(current) || current < 1) throw new Error("catalog sequence must be a positive integer");
  if (!Number.isSafeInteger(latest) || latest < 0) throw new Error("latest release sequence must be a non-negative integer");
  if (tagExists) throw new Error(`catalog-${current} already exists; immutable releases cannot be replaced`);
  if (current <= latest) throw new Error(`catalog sequence ${current} is not greater than latest immutable sequence ${latest}`);
  return true;
}

function parseSequence(value, label, fallback = 0) {
  if (value === undefined || value === "") return fallback;
  if (!/^\d+$/.test(value)) throw new Error(`${label} must be a non-negative integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${label} is out of range`);
  return parsed;
}

const current = Number(JSON.parse(await readFile(new URL("../catalog.json", import.meta.url), "utf8")).sequence);
const latest = parseSequence(process.env.STORE_LATEST_SEQUENCE, "latest release sequence");
checkReleaseSequence(current, latest, { tagExists: process.env.STORE_TAG_EXISTS === "true" });
console.log(`Catalog sequence ${current} is monotonic after ${latest || "no prior release"}.`);
