import fs from 'node:fs';
import path from 'node:path';
import type {Plugin} from 'vite';
import {loadKeyFile} from './keys.js';
import {publicationDisplay,publicationURL} from './display.js';
import {collectBuildFiles,packDirectory} from './pack.js';
import {verifyEntryBytes,readPublicationBytes,verifyPublication,masterSeedOfBytes} from './format.js';
export type KeymasterPublisherMode = "url" | "files" | "both";

export interface KeymasterPublisherOptions {
  /** url：仅 URL 来源证明；files：仅 Files 整包签名；both：先 URL 证明再整入口签名。 */
  mode: KeymasterPublisherMode;
  name: string;
  description?: string;
  icon: string;
  resourceBaseUrl?: string;
  /** 本地 App 私钥文件路径（相对路径按进程工作目录解析）；缺失或非法直接失败，不自动生成。 */
  keyFile: string;
  /** url/both 必填：完整入口 URL，从中计算签名 origin。 */
  url?: string;
  /**
   * 机器可读摘要输出路径（必须在应用文件树之外）；缺省 false 表示仅控制台输出。
   */
  manifestFile?: string | false;
}

export interface KeymasterPublishSummary {
  mode: KeymasterPublisherMode;
  appPublicKeyHex: string;
  origin?: string;
  indexseedhashhex?: string;
  signatureHex?: string;
  files: number;
  entryBytes: number;
  totalBytes: number;
}

function fail(message: string): never {
  throw new Error(`[keymaster-publisher] ${message}`);
}

function resolveKeyFile(keyFile: string): string {
  if (!keyFile || typeof keyFile !== "string") fail("keyFile 必填：指向本地 App 私钥文件，不自动生成");
  return path.resolve(keyFile);
}

export function keymasterPublisher(options: KeymasterPublisherOptions): Plugin {
  if (!options || typeof options !== "object") fail("options 必填");
  const mode = options.mode;
  if (mode !== "url" && mode !== "files" && mode !== "both") fail("mode 必须为 url|files|both");
  const keyFile = resolveKeyFile(options.keyFile);
  const entry = "index.html";
  let configuredOrigin: string | undefined;
  if (mode === "url" || mode === "both") {
    if (typeof options.url !== "string" || !options.url) fail("url/both 模式必须提供完整 URL");
    configuredOrigin = new URL(publicationURL(options.url)).origin;
  }
  publicationDisplay(options);
  const manifestFile = options.manifestFile ?? false;
  if (manifestFile !== false && (typeof manifestFile !== "string" || !manifestFile)) fail("manifestFile must be a nonempty external path or false");

  let outputDirectory: string | undefined;
  const plugin: Plugin = {
    name: "keymaster-publisher",
    enforce: "post",
    apply: "build",
    configResolved(config) {
      if (config.build.watch || config.build.write === false) fail("publication requires a completed build with write enabled and watch disabled");
      // Rollup orders post hooks by plugin position. Keep the sequential signing
      // hook after every other closeBundle hook, including other post hooks.
      const plugins = config.plugins as Plugin[];
      const index = plugins.indexOf(plugin);
      if (index >= 0) plugins.push(...plugins.splice(index, 1));
    },
    writeBundle(outputOptions) {
      if (outputDirectory && outputDirectory !== outputOptions.dir) fail("multiple output directories are unsupported");
      outputDirectory = outputOptions.dir;
    },
    closeBundle: { order: "post", sequential: true, async handler() {
      // Vite 的输出目录：仅处理已写出的最终文件。
      const outDir = outputDirectory;
      if (!outDir) return;
      if (!outDir) fail("无法确定输出目录");
      const outAbs = path.resolve(outDir as string);
      if (!fs.existsSync(outAbs) || !fs.lstatSync(outAbs).isDirectory()) fail(`输出目录不存在：${outAbs}`);

      const key = loadKeyFile(keyFile);
      const workRoot = fs.mkdtempSync(path.join(path.dirname(outAbs), ".keymaster-publisher-"));
      // 候选目录：复制最终输出后在副本上处理，成功后原子替换。
      const candidate = path.join(workRoot, "candidate");
      const backup = path.join(workRoot, "backup");
      try {
        fs.cpSync(outAbs, candidate, { recursive: true });
        const entryRel = entry.split("/").join(path.sep);
        if (!fs.existsSync(path.join(candidate, entryRel))) fail(`入口文件缺失：${entry}`);
        const packed=packDirectory({dir:candidate,privateKeyHex:key.privateKeyHex,mode,name:options.name,description:options.description,icon:options.icon,url:options.url,resourceBaseUrl:options.resourceBaseUrl});
        let summary:KeymasterPublishSummary={mode,appPublicKeyHex:packed.appPublicKeyHex,origin:configuredOrigin,...mode!=='url'?{indexseedhashhex:packed.indexseedhashhex}:{},signatureHex:packed.signatureHex,files:packed.files.length,entryBytes:packed.entryBytes,totalBytes:packed.totalBytes};
        verifyPublication(readPublicationBytes(fs.readFileSync(path.join(candidate,entryRel))),mode==='files'?undefined:options.url);
        const finalFiles = collectBuildFiles(candidate);
        if (mode === "url") {
          summary.files = finalFiles.length - 1;
          summary.totalBytes = finalFiles.reduce((sum, file) => sum + fs.statSync(path.join(candidate, file)).size, 0);
        }
        for (const file of finalFiles) {
          const bytes = fs.readFileSync(path.join(candidate, file));
          if (bytes.includes(key.privateKeyHex) || bytes.includes(Buffer.from(key.privateKeyHex, "hex"))) fail("private key material found in build output");
        }
        if (mode !== "url") {
          const verified = verifyEntryBytes(new Uint8Array(fs.readFileSync(path.join(candidate, entryRel))));
          const expected = [entry, ...verified.publication.files!.files.map(file => file.path)].sort();
          if (JSON.stringify(finalFiles) !== JSON.stringify(expected)) fail("output tree differs from signed manifest");
          for (const file of verified.publication.files!.files) {
            const bytes = fs.readFileSync(path.join(candidate, file.path));
            if (bytes.length !== file.size || masterSeedOfBytes(bytes).seedhashhex !== file.seedhashhex) fail("output file differs from signed manifest");
          }
        }

        if (typeof manifestFile === "string" && manifestFile) {
          const target = path.resolve(manifestFile);
          const parent = fs.realpathSync(path.dirname(target));
          const realTarget = path.join(parent, path.basename(target));
          const realOut = fs.realpathSync(outAbs);
          if (realTarget === realOut || realTarget.startsWith(realOut + path.sep)) fail("manifestFile 必须在应用文件树之外");
          if (fs.existsSync(target) && fs.lstatSync(target).isSymbolicLink()) fail("manifestFile cannot be a symlink");
          fs.writeFileSync(target, `${JSON.stringify(summary, null, 2)}\n`);
        }

        // 原子替换：候选目录整体搬入输出目录。
        fs.rmSync(backup, { recursive: true, force: true });
        fs.renameSync(outAbs, backup);
        try {
          fs.renameSync(candidate, outAbs);
        } catch (err) {
          fs.renameSync(backup, outAbs);
          throw err;
        }
        fs.rmSync(backup, { recursive: true, force: true });

        // 摘要输出：控制台一行 JSON（不含私钥）；机器读取写到应用文件树之外。
        console.log(`[keymaster-publisher] ${JSON.stringify({ ...summary, signatureHex: summary.signatureHex ? `${summary.signatureHex.slice(0, 16)}…` : undefined })}`);

      } finally {
        // Preserve the backup if restoring it failed; never erase recovery data.
        if (!fs.existsSync(backup)) fs.rmSync(workRoot, { recursive: true, force: true });
      }
    } },
  };
  return plugin;
}
