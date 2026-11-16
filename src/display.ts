/** Build configuration only; no source meta or remote icon input. */
export interface PublicationDisplay {name:string;description:string;icon:string}
export function publicationDisplay(input:{name:unknown;description?:unknown;icon:unknown}):PublicationDisplay {
 const result={} as PublicationDisplay;
 for(const [field,limit] of [['name',120],['description',2000],['icon',512]] as const){
  const value=field==='description'&&input[field]===undefined?'':input[field];
  if(typeof value!=='string')throw new Error(`${field} must be a string`);
  const text=field==='icon'?value:value.trim();
  if((field!=='description'&&!text)||[...text].length>limit||/[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(text))throw new Error(`${field} is empty or invalid`);
  result[field]=text;
 }
 const p=result.icon;
 if(p.startsWith('/')||p.includes('\\')||/^[a-z][a-z0-9+.-]*:/i.test(p)||p.split('/').some(s=>!s||s==='.'||s==='..'))throw new Error('icon must be a build-relative file path');
 return result;
}
export function publicationURL(value:unknown):string {
 if(typeof value!=='string')throw new Error('complete HTTP(S) URL required');
 const u=new URL(value);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)throw new Error('HTTP(S) URL without credentials required');return u.href;
}
export function iconURL(address:string,icon:string,resourceBaseUrl?:string):string {
 const base=resourceBaseUrl===undefined?new URL('.',address).href:publicationURL(resourceBaseUrl);
 if(!base.endsWith('/')||new URL(base).search||new URL(base).hash)throw new Error('resourceBaseUrl must be an HTTP(S) directory ending in /');
 return new URL(icon.split('/').map(encodeURIComponent).join('/'),base).href;
}
