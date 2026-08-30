import { readFile, writeFile } from "node:fs/promises";
import { createPublicKey, sign, verify } from "node:crypto";
import { validateCatalogDocument, validateCatalog, PRODUCTION_KEY_ID, PRODUCTION_PUBLIC_KEY } from "./validate-catalog.mjs";

const privateKey = process.env.STORE_SIGNING_KEY;
if (!privateKey) throw new Error("STORE_SIGNING_KEY is required");

const bytes = await readFile(new URL("../catalog.json", import.meta.url));
const document = JSON.parse(bytes);
validateCatalogDocument(document);

const publicDer = createPublicKey(privateKey).export({ type: "spki", format: "der" });
const publicRaw = publicDer.subarray(publicDer.length - 32).toString("base64");
if (publicRaw !== PRODUCTION_PUBLIC_KEY) throw new Error("signing key does not match production trust");

const signature = sign(null, bytes, privateKey);
if (!verify(null, bytes, createPublicKey(privateKey), signature)) {
  throw new Error("signature self-check failed");
}

const envelope = {
  bytes: bytes.toString("base64"),
  signatures: {
    schema_version: 1,
    signatures: [
      {
        key_id: PRODUCTION_KEY_ID,
        algorithm: "ed25519",
        signature: signature.toString("base64")
      }
    ]
  }
};
validateCatalog(document, envelope, { strictEnvelope: true, catalogBytes: bytes });
await writeFile(
  new URL("../catalog.envelope.json", import.meta.url),
  `${JSON.stringify(envelope, null, 2)}\n`
);
