#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { validateCatalog, validateEnvelope } from "./validate-catalog.mjs";

const catalogBytes = await readFile(new URL("../catalog.json", import.meta.url));
const catalog = JSON.parse(catalogBytes);
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signature = sign(null, catalogBytes, privateKey);
if (!verify(null, catalogBytes, publicKey, signature)) throw new Error("ephemeral signature self-check failed");
const rawPublicKey = publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("base64");
const envelope = {
  bytes: catalogBytes.toString("base64"),
  signatures: {
    schema_version: 1,
    signatures: [{ key_id: "kosmos-store-2026", algorithm: "ed25519", signature: signature.toString("base64") }],
  },
};
validateCatalog(catalog, envelope, { publicKey: rawPublicKey, strictEnvelope: true, catalogBytes });
validateEnvelope(envelope, { publicKey: rawPublicKey, strictEnvelope: true, catalogBytes });
console.log(`Dry-run signed and verified exact catalog bytes for sequence ${catalog.sequence}; no production key or release was used.`);
