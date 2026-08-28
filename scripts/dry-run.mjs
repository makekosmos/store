#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { validateCatalog } from "./validate-catalog.mjs";

const catalogBytes = await readFile(new URL("../catalog.json", import.meta.url));
const catalog = JSON.parse(catalogBytes);
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signature = sign(null, catalogBytes, privateKey);
const envelope = {
  bytes: catalogBytes.toString("base64"),
  signatures: {
    schema_version: 1,
    signatures: [{ key_id: "kosmos-store-2026", algorithm: "ed25519", signature: signature.toString("base64") }],
  },
};
if (!verify(null, catalogBytes, publicKey, signature)) throw new Error("ephemeral signature self-check failed");
console.log(`Dry-run signed and verified catalog sequence ${catalog.sequence}; no production key or release was used.`);
