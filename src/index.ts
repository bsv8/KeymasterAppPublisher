/** Keymaster 应用发布 Vite 插件。
 *
 * 唯一公开入口为 `keymasterPublisher()` 工厂；不提供通用 CLI、不连接钱包、
 * 不依赖 `keymaster-connect`、不上传市场、不抓取已部署网站、不启动常驻服务。
 * 私钥只存于本地密钥文件，缺失或非法直接失败，不自动生成。
 */
export { keymasterPublisher } from "./plugin.js";
export type { KeymasterPublisherMode, KeymasterPublisherOptions, KeymasterPublishSummary } from "./plugin.js";
