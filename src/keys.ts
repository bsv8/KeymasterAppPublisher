/** App 私钥本地管理：只读文件并校验，不生成、不上传、不打日志。
 *
 * 密钥文件缺失或非法时明确失败；插件不自动创建新身份。
 * 返回的私钥材料调用方不得输出到日志、产物或 source map。
 */
import fs from "node:fs";
import { secp256k1 } from "@noble/curves/secp256k1.js";

export interface AppKeyFile {
  version: 1;
  kind: "keymaster-app-key";
  appPublicKeyHex: string;
  /** 32 字节私钥小写 hex。 */
  privateKeyHex: string;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/** 读取本地密钥文件并校验版本、种类与密钥对一致性。 */
export function loadKeyFile(keyFile: string): AppKeyFile {
  let raw: string;
  try {
    raw = fs.readFileSync(keyFile, "utf8");
  } catch {
    throw new Error(`app key file is missing or unreadable: ${keyFile} (publisher never creates identities; provide an existing key file)`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("app key file is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("app key file is invalid");
  const k = parsed as Record<string, unknown>;
  if (k.version !== 1 || k.kind !== "keymaster-app-key") throw new Error("app key file version/kind mismatch");
  if (typeof k.privateKeyHex !== "string" || !/^[0-9a-f]{64}$/.test(k.privateKeyHex)) {
    throw new Error("app key file private key is invalid");
  }
  const priv = new Uint8Array(Buffer.from(k.privateKeyHex, "hex"));
  let derived: string;
  try {
    derived = hex(secp256k1.getPublicKey(priv, true));
  } catch {
    throw new Error("app key file private key is out of range");
  }
  if (typeof k.appPublicKeyHex !== "string" || k.appPublicKeyHex !== derived) {
    throw new Error("app key file public key does not match private key");
  }
  return { version: 1, kind: "keymaster-app-key", appPublicKeyHex: derived, privateKeyHex: k.privateKeyHex as string };
}
