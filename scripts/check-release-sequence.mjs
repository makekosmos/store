#!/usr/bin/env node
const current = Number(JSON.parse(await (await fetch(new URL("../catalog.json", import.meta.url))).text()).sequence);
const latest = Number(process.env.STORE_LATEST_SEQUENCE || 0);
if (!Number.isSafeInteger(current) || current < 1) throw new Error("catalog sequence must be a positive integer");
if (latest && (!Number.isSafeInteger(latest) || current <= latest)) throw new Error(`catalog sequence ${current} is not greater than latest immutable sequence ${latest}`);
console.log(`Catalog sequence ${current} is monotonic after ${latest || "no prior release"}.`);
