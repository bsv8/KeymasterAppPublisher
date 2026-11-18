import {publicationDisplay,publicationURL,iconURL} from './display.js';
import fs from 'node:fs';
import path from 'node:path';
import {secp256k1} from '@noble/curves/secp256k1.js';
import {assertAppPublicKeyHex,masterSeedOfBytes,insertEmptyPublication,fillPublication,signPublication,readPublicationBytes,verifyPublication,verifyEntryBytes,type AppFileEntry,type Publication} from './format.js';
export interface PackOptions {
  appVersion: string;
 dir:string;privateKeyHex:string;mode:'url'|'files'|'both';name:string;description?:string;icon:string;url?:string;resourceBaseUrl?:string;mimeMap?:Record<string,string>;
}
export interface PackResult {
  appPublicKeyHex: string;
  indexseedhashhex: string;
  signatureHex: string;
  files: AppFileEntry[];
  entryBytes: number;
  totalBytes: number;
}

const DEFAULT_MIME: Record<string, string> = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".map": "application/json",
  ".wasm": "application/wasm",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".otf": "font/otf",
  ".txt": "text/plain",
};

function mimeFor(rel: string, mimeMap: Record<string, string>): string {
  const ext = path.posix.extname(rel).toLowerCase();
  return mimeMap[ext] ?? DEFAULT_MIME[ext] ?? "application/octet-stream";
}

/** 相对路径是否安全（拒绝穿越、绝对路径、反斜杠、空段）。 */
function isSafeRel(rel: string): boolean {
  if (!rel || rel.length > 512 || rel.startsWith("/") || rel.includes("\\") || rel.includes("\0")) return false;
  if (/[\u0000-\u001f\u007f]/.test(rel)) return false;
  const segments = rel.split("/");
  return !segments.some((s) => !s || s === "." || s === ".." || s.length > 255);
}

/** 递归收集目录全部普通文件（相对 POSIX 路径排序）；拒绝符号链接与特殊文件。 */
export function collectBuildFiles(rootDir: string): string[] {
  const root = path.resolve(rootDir);
  const stat = fs.statSync(root);
  if (!stat.isDirectory()) throw new Error(`build dir is not a directory: ${rootDir}`);
  const out: string[] = [];
  const walk = (abs: string) => {
    const entries = fs.readdirSync(abs, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const e of entries) {
      const full = path.join(abs, e.name);
      const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) throw new Error(`symlinks are not allowed in build dir: ${path.relative(root, full)}`);
      if (st.isDirectory()) {
        walk(full);
      } else if (st.isFile()) {
        const rel = path.relative(root, full).split(path.sep).join("/");
        if (!isSafeRel(rel)) throw new Error(`unsafe path in build dir: ${rel}`);
        out.push(rel);
      } else {
        throw new Error(`special files are not allowed in build dir: ${path.relative(root, full)}`);
      }
    }
  };
  walk(root);
  out.sort();
  return out;
}

/** 打包并签署已写出目录（原地修改入口文件）。返回产物摘要；私钥不出本机。 */
export function packDirectory(opts: PackOptions): PackResult {
  const root = path.resolve(opts.dir);
  const entry = "index.html";
  const rels = collectBuildFiles(root);
  if (!rels.includes(entry)) throw new Error(`build dir must contain entry ${entry} at top level`);
  const privLower = opts.privateKeyHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(privLower)) throw new Error("private key is invalid");
  const appPublicKeyHex = assertAppPublicKeyHex(
    Buffer.from(secp256k1.getPublicKey(Buffer.from(privLower, "hex"), true)).toString("hex"),
  );

  const files: AppFileEntry[] = [];
  let totalBytes = 0;
  for (const rel of rels) {
    if (rel === entry) continue;
    const bytes = fs.readFileSync(path.join(root, rel));
    totalBytes += bytes.length;
    const { seedhashhex } = masterSeedOfBytes(new Uint8Array(bytes));
    files.push({ path: rel, seedhashhex, size: bytes.length, mime: mimeFor(rel, opts.mimeMap ?? {}) });
  }
  const display=publicationDisplay(opts);
  const icon=files.find(f=>f.path===display.icon);if(!icon)throw new Error('icon must exist in final build files');
  const templatePath=path.join(root,entry);
  const aBytes=insertEmptyPublication(fs.readFileSync(templatePath));
  const payload:Publication={version:1,appVersion:opts.appVersion,kind:opts.mode,appPublicKeyHex,name:display.name,description:display.description};
  if(opts.mode!=='files') {const address=publicationURL(opts.url);payload.url={address,icon:iconURL(address,display.icon,opts.resourceBaseUrl)}}
  if(opts.mode!=='url')payload.files={entrySeedhashhex:masterSeedOfBytes(aBytes).seedhashhex,icon:icon.seedhashhex,files};
  const proof=signPublication(payload,privLower);const bBytes=fillPublication(aBytes,proof);
  fs.writeFileSync(templatePath,bBytes);
  verifyPublication(readPublicationBytes(fs.readFileSync(templatePath)),payload.url?.address);
  if(payload.files)verifyEntryBytes(fs.readFileSync(templatePath));
  return {appPublicKeyHex,indexseedhashhex:masterSeedOfBytes(bBytes).seedhashhex,signatureHex:proof.signatureHex,files,entryBytes:bBytes.length,totalBytes:totalBytes+bBytes.length};
}
