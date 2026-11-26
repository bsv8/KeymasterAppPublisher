# KeymasterAppPublisher

仅用于 `vite build` 的发布插件，不依赖 Connect SDK。Vite 为宿主依赖。

```ts
import { defineConfig } from 'vite';
import { keymasterPublisher } from 'keymaster-app-publisher';

export default defineConfig({
  plugins: [keymasterPublisher({appVersion:"0.1.2",
    mode: 'both', // url | files | both
    keyFile: '/本机已有/app.key.json',
    name: '我的应用',
    description: '应用介绍',
    icon: 'assets/icon.png',
    url: 'https://example.com/app/index.php',
    resourceBaseUrl: 'https://example.com/app/'
  })]
});
```

url/both 必须提供完整 URL，由插件解析 canonical origin；files 无需 URL。只读取已有私钥文件，不自动生成身份。文件格式为 `{version:1,kind:"keymaster-app-key",appPublicKeyHex,privateKeyHex}`，公钥必须匹配私钥。私钥只存本机，不入 Git，不进入日志、浏览器模块或构建资源。

插件只在构建运行。其他 closeBundle 转换先完成，再由最后的串行 post closeBundle 完整收集最终文件、签署及自校验；同盘候选成功后替换输出，失败使构建失败并保留未签名输出。所有模式生成唯一 keymaster-app 记录和 JSON 外置总签名；Files/Both 额外绑定空 content 的原始入口 MasterSeed。重复构建必须从干净输出开始。

构建日志输出摘要；可用 `manifestFile` 指定应用树外的机器可读摘要路径，父目录须已存在。应用树不写 keymaster-manifest.json。插件不连接钱包、不抓取网站、不上传市场、不执行应用代码、不启动服务，不提供 CLI 或密钥管理入口。市场页面或接口独立接受 URL、Files、组合提交。外部依赖运行时策略归 Client/宿主。

开发使用 `pnpm install`、`pnpm run typecheck`、`pnpm run build`。工程验收运行 `pnpm run e2e:publisher`，发布格式跨语言向量运行 `pnpm run parity:app-publication`。协议正文见[应用发布与公钥身份](../BSV8_Engineering/docs/keymaster.cc/requirements/应用发布与公钥身份.md)。


资料只从插件配置读取。名称必填、最多120 Unicode码点；介绍可选、最多2000码点。icon 必须是最终构建目录内真实普通文件的相对路径，三个模式均检查其存在。URL 图标按 resourceBaseUrl（缺省首页所在目录）逐段编码；Files 图标记录 MasterSeed seedhash，不是路径或普通 SHA256。源码已有发布记录或旧发布 meta 会明确失败。发布记录不设证明专用长度上限，只受入口 HTML 读取上限、清单项数与各传输通道通用帧限制约束；不删减 Both 文件清单。

应用发布版本 `appVersion` 为必填签名字段，格式为 `0.1.2`（三段非负整数，不允许前导零、前缀或后缀），与格式字段 `version:1` 无关。同公钥高版本及同版本的后一次成功提交整份覆盖全部发布参数；低版本拒绝。当前最多一个 URL 与一个 Files 渠道，缺席渠道清除，用户权限和收藏不属于发布参数。
