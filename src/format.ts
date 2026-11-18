import {parse} from 'parse5';
import {secp256k1} from '@noble/curves/secp256k1.js';
import {sha256} from '@noble/hashes/sha2.js';
import {publicationURL} from './display.js';
export const PUBLICATION_META='keymaster-app';
export const PUBLICATION_DOMAIN='keymaster.app-publication.v1';
export const MAX_ENTRY_BYTES=16*1024*1024;
export const MAX_FILES_ENTRIES=100000;
export const APP_FILE_BLOCK_SIZE=256*1024;
export class AppPublicationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AppPublicationError";
  }
}

/** 有效 secp256k1 压缩公钥，小写 hex，33 字节。严格要求小写。 */
export function assertAppPublicKeyHex(value: unknown, field = "appPublicKeyHex"): string {
  if (typeof value !== "string" || !/^(02|03)[0-9a-f]{64}$/.test(value)) {
    throw new AppPublicationError(`${field} must be a 33-byte compressed secp256k1 public key in lower-case hex`);
  }
  try {
    secp256k1.Point.fromHex(value);
  } catch {
    throw new AppPublicationError(`${field} is not a valid secp256k1 public key`);
  }
  return value;
}

/** 64 字节紧凑签名的小写 hex 形式（128 字符）。 */
export function assertSignatureHex(value: unknown, field = "signatureHex"): string {
  if (typeof value !== "string" || !/^[0-9a-f]{128}$/.test(value)) {
    throw new AppPublicationError(`${field} must be 128 lower-case hex chars`);
  }
  return value;
}

function assertPrivKeyHex(value: unknown): Uint8Array {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new AppPublicationError("private key must be 32-byte hex");
  }
  const bytes = hexToBytes(value.toLowerCase());
  if (bytes.every((b) => b === 0)) throw new AppPublicationError("private key must not be zero");
  try {
    secp256k1.getPublicKey(bytes, true);
  } catch {
    throw new AppPublicationError("private key is out of range");
  }
  return bytes;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(input: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) throw new AppPublicationError("payload is not base64url");
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) base64 += "=";
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** 域隔离哈希：SHA256(UTF8(domain) || NUL || payload)。 */
function domainHash(domain: string, payload: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(domain);
  const input = new Uint8Array(prefix.length + 1 + payload.length);
  input.set(prefix, 0);
  input[prefix.length] = 0;
  input.set(payload, prefix.length + 1);
  return sha256(input);
}

function signHash(hash: Uint8Array, privKey: Uint8Array): string {
  if (hash.length !== 32 || privKey.length !== 32) throw new AppPublicationError("signing input length mismatch");
  // 输入已是 SHA256 摘要：关闭重复预哈希；低 S 由 SDK 默认保证。
  const sig = secp256k1.sign(hash, privKey, { prehash: false, lowS: true });
  if (sig.length !== 64) throw new AppPublicationError("compact signature length mismatch");
  return bytesToHex(sig);
}

function verifyHash(hash: Uint8Array, sigHex: string, pubKeyHex: string): boolean {
  try {
    const sig = hexToBytes(sigHex);
    const pub = hexToBytes(pubKeyHex);
    return secp256k1.verify(sig, hash, pub, { prehash: false, format: "compact", lowS: true });
  } catch {
    return false;
  }
}

/** RFC 8785 兼容的规范 JSON（键排序，无 HTML 转义语义分歧）。 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new AppPublicationError("payload contains a non-finite number");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJson).join(",")}]`;
  }
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    const entries = Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(object[key])}`);
    return `{${entries.join(",")}}`;
  }
  throw new AppPublicationError("payload contains an unsupported value");
}

/* ============== 来源解析（WHATWG URL 语义，Node 实现） ============== */

export interface AppFileEntry {path:string;mime:string;size:number;seedhashhex:string}
export interface Publication {version:1;appVersion:string;kind:'url'|'files'|'both';appPublicKeyHex:string;name:string;description:string;url?:{address:string;icon:string};files?:{entrySeedhashhex:string;icon:string;files:AppFileEntry[]}}
export interface PublicationProof {publication:Publication;signatureHex:string}
function fields(value:any,keys:string[]):void {if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!==keys.sort().join(','))throw new Error('publication fields invalid')}
function text(value:unknown,max:number,required=true):string {if(typeof value!=='string'||value!==value.trim()||(required&&!value)||[...value].length>max||/[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(value))throw new Error('publication text invalid');return value}
function seedhash(value:unknown):string {if(typeof value!=='string'||!/^[0-9a-f]{64}$/.test(value))throw new Error('invalid seedhashhex');return value}
export function manifestPath(value:unknown):string {if(typeof value!=='string'||!value||new TextEncoder().encode(value).length>512||value==='index.html'||value.startsWith('/')||value.includes('\\')||/^[a-z][a-z0-9+.-]*:/i.test(value)||/[\u0000-\u001f\u007f\ud800-\udfff]/u.test(value)||value.split('/').some(s=>!s||s==='.'||s==='..'||new TextEncoder().encode(s).length>255))throw new Error('unsafe manifest path');return value}
export function validatePublication(value:unknown):Publication {
 const p=value as Publication;const kind=p?.kind;
 if(!['url','files','both'].includes(kind))throw new Error('invalid publication kind');
 fields(p,['version','appVersion','kind','appPublicKeyHex','name','description',...(kind!=='files'?['url']:[]),...(kind!=='url'?['files']:[])]);
 validateAppVersion(p.appVersion);if(p.version!==1)throw new Error('invalid publication version');assertAppPublicKeyHex(p.appPublicKeyHex);text(p.name,120);text(p.description,2000,false);
 if(kind!=='files'){fields(p.url,['address','icon']);for(const v of [p.url!.address,p.url!.icon])if(publicationURL(v)!==v||v.length>8192)throw new Error('noncanonical publication URL')}
 if(kind!=='url'){fields(p.files,['entrySeedhashhex','icon','files']);seedhash(p.files!.entrySeedhashhex);seedhash(p.files!.icon);if(!Array.isArray(p.files!.files)||p.files!.files.length>MAX_FILES_ENTRIES)throw new Error('invalid manifest');let last='';for(const f of p.files!.files){fields(f,['path','mime','size','seedhashhex']);manifestPath(f.path);if(f.path<=last)throw new Error('manifest must be sorted and unique');last=f.path;text(f.mime,256);if(!Number.isSafeInteger(f.size)||f.size<0)throw new Error('invalid file size');seedhash(f.seedhashhex)}if(!p.files!.files.some(f=>f.seedhashhex===p.files!.icon))throw new Error('icon seed absent from manifest')}
 return p;
}
export function canonicalPublicationJSON(p:Publication):string{return canonicalizeJson(validatePublication(p))}
export function signPublication(p:Publication,key:string):PublicationProof {return {publication:validatePublication(p),signatureHex:signHash(domainHash(PUBLICATION_DOMAIN,new TextEncoder().encode(canonicalPublicationJSON(p))),assertPrivKeyHex(key))}}
export function encodePublication(proof:PublicationProof):string {fields(proof,['publication','signatureHex']);assertSignatureHex(proof.signatureHex);const content=base64UrlEncode(new TextEncoder().encode(canonicalPublicationJSON(proof.publication)))+'.'+proof.signatureHex;return content}
export function decodePublication(content:string):PublicationProof {
 const m=/^([A-Za-z0-9_-]+)\.([0-9a-f]{128})$/.exec(content);if(!m)throw new Error('invalid publication encoding');
 const bytes=base64UrlDecode(m[1]);if(base64UrlEncode(bytes)!==m[1])throw new Error('noncanonical base64url');
 const json=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);const publication=validatePublication(JSON.parse(json));
 // Equality also rejects duplicate keys, whitespace and alternative escapes.
 if(canonicalPublicationJSON(publication)!==json)throw new Error('noncanonical publication JSON');return {publication,signatureHex:m[2]};
}
export function verifyPublication(proof:PublicationProof,expectedOrigin?:string):Publication {
 encodePublication(proof);const p=proof.publication;
 if(!verifyHash(domainHash(PUBLICATION_DOMAIN,new TextEncoder().encode(canonicalPublicationJSON(p))),proof.signatureHex,p.appPublicKeyHex))throw new Error('publication signature mismatch');
 if(expectedOrigin!==undefined&&(!p.url||new URL(p.url.address).origin!==new URL(expectedOrigin).origin))throw new Error('publication origin mismatch');return p;
}
const oldNames=new Set(['keymaster-app-files','keymaster-app-url-proof','keymaster-app-name','keymaster-app-description','keymaster-app-icon']);
function inspect(bytes:Uint8Array):{start:number;end:number;headEnd:number;content:string}|null {
 if(bytes.length>MAX_ENTRY_BYTES)throw new Error('entry too large');
 const html=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
 // Mask BOM for parser semantics without shifting UTF-16 source offsets.
 const source=html.startsWith('\uFEFF')?' '+html.slice(1):html;const duplicates:number[]=[];
 const doc=parse(source,{sourceCodeLocationInfo:true,onParseError:e=>{if(e.code==='duplicate-attribute')duplicates.push(e.startOffset)}}) as any;
 let result:any=null;let headEnd=-1;
 function walk(n:any){if(n.tagName==='head'&&n.sourceCodeLocation?.endTag)headEnd=n.sourceCodeLocation.endTag.startOffset;
 if(n.tagName==='meta'){const name=n.attrs.find((a:any)=>a.name==='name')?.value;if(oldNames.has(name))throw new Error('remove obsolete publication meta: '+name);if(name===PUBLICATION_META){const loc=n.sourceCodeLocation;const head=n.parentNode;if(result||!loc||head?.tagName!=='head'||!head.sourceCodeLocation?.endTag||loc.startOffset<head.sourceCodeLocation.startTag.endOffset||loc.endOffset>head.sourceCodeLocation.endTag.startOffset||duplicates.some(p=>p>=loc.startOffset&&p<loc.endOffset))throw new Error('publication must be unique in actual head without duplicate attributes');const raw=html.slice(loc.startOffset,loc.endOffset);const m=/^<meta name="keymaster-app" content="([A-Za-z0-9_.-]*)">$/.exec(raw);if(!m)throw new Error('publication tag must use fixed syntax');const offset=loc.startOffset+raw.indexOf('content="')+9;const start=new TextEncoder().encode(html.slice(0,offset)).length;result={start,end:start+m[1].length,headEnd,content:m[1]}}}
 for(const c of n.childNodes??[])walk(c);if(n.content)walk(n.content)}walk(doc);
 if(headEnd<0)throw new Error('explicit head required');if(result)return {...result,headEnd};return null;
}
export function insertEmptyPublication(bytes:Uint8Array):Uint8Array {
 if(inspect(bytes))throw new Error('remove existing keymaster-app record');
 const html=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);const doc=parse(html.startsWith('\uFEFF')?' '+html.slice(1):html,{sourceCodeLocationInfo:true}) as any;
 const head=doc.childNodes.find((n:any)=>n.tagName==='html')?.childNodes.find((n:any)=>n.tagName==='head');const offset=head?.sourceCodeLocation?.endTag?.startOffset;if(offset===undefined)throw new Error('explicit head required');
 const position=new TextEncoder().encode(html.slice(0,offset)).length;return splice(bytes,position,position,new TextEncoder().encode('<meta name="keymaster-app" content="">'));
}
function splice(bytes:Uint8Array,start:number,end:number,value:Uint8Array):Uint8Array {const out=new Uint8Array(start+value.length+bytes.length-end);out.set(bytes.subarray(0,start));out.set(value,start);out.set(bytes.subarray(end),start+value.length);return out}
export function fillPublication(bytes:Uint8Array,proof:PublicationProof):Uint8Array {const rec=inspect(bytes);if(!rec||rec.content)throw new Error('empty publication record required');return splice(bytes,rec.start,rec.end,new TextEncoder().encode(encodePublication(proof)))}
export function readPublicationBytes(bytes:Uint8Array):PublicationProof {const rec=inspect(bytes);if(!rec)throw new Error('publication missing');return decodePublication(rec.content)}
export function verifyEntryBytes(bytes:Uint8Array){const rec=inspect(bytes);if(!rec)throw new Error('publication missing');const proof=decodePublication(rec.content);const p=verifyPublication(proof);if(!p.files)throw new Error('Files channel required');const aBytes=splice(bytes,rec.start,rec.end,new Uint8Array());if(masterSeedOfBytes(aBytes).seedhashhex!==p.files.entrySeedhashhex)throw new Error('entry seed mismatch');return {publication:p,proof,aBytes,...masterSeedOfBytes(bytes)}}
export function masterSeedOfBytes(data: Uint8Array): { seed: Uint8Array; seedhashhex: string } {
  const digests: Uint8Array[] = [];
  for (let offset = 0; offset < data.length; offset += APP_FILE_BLOCK_SIZE) {
    const block = data.slice(offset, Math.min(offset + APP_FILE_BLOCK_SIZE, data.length));
    digests.push(sha256(block));
  }
  const seed = new Uint8Array(digests.length * 32);
  digests.forEach((d, i) => seed.set(d, i * 32));
  return { seed, seedhashhex: bytesToHex(sha256(seed)) };
}

/** 严格三段发布版本；按十进制整数比较，避免字符串排序及浮点精度问题。 */
export function validateAppVersion(value: unknown): string {
 if (typeof value !== "string" || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(value)) throw new Error("Invalid appVersion");
 return value;
}
export function compareAppVersions(a: string, b: string): number {
 const left=validateAppVersion(a).split("."), right=validateAppVersion(b).split(".");
 for(let i=0;i<3;i++){const x=left[i]!,y=right[i]!;if(x.length!==y.length)return x.length<y.length?-1:1;if(x!==y)return x<y?-1:1;}return 0;
}
