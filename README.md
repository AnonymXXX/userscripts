# 油猴脚本集（UserScripts）

个人 Tampermonkey 脚本集合，集中管理、统一安装与更新。

## 脚本列表

| 脚本 | 目录 | 功能 |
| --- | --- | --- |
| [`multi-2fa-autofill.user.js`](multi-2fa-autofill.user.js) | 根目录 | 多账号 TOTP 管理器：otpauth URI 批量导入、站点匹配自动填充、悬浮面板一键复制，仅在页面存在验证码输入框时显示 |
| [`delta-force-map-helper/`](delta-force-map-helper/) | 子目录 | 三角洲行动官方地图助手（AZ3 出生点/大保险箱点位等），内含独立 README 与素材 |

## 安装

1. 安装 [Tampermonkey](https://www.tampermonkey.net/) 浏览器扩展。
2. 双击/拖拽对应的 `.user.js` 文件到浏览器，确认安装或更新。
3. 更新脚本时，油猴会按脚本内的 `@name` 自动匹配覆盖旧版本。

## 脚本约定

- 每个脚本独立成文件，支持单独安装和更新。
- 带素材/多文件的脚本放在独立子目录中，保持项目结构完整。
- `multi-2fa-autofill.user.js` 的 TOTP 密钥保存在油猴本地存储（`GM_setValue`），更新脚本不影响已存账号。
