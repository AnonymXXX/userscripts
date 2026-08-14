# Multi 2FA Autofill（多平台 2FA 自动填充）

多账号 TOTP 管理器油猴脚本：集中管理所有站点的 2FA 密钥，登录页自动填充验证码，支持 otpauth URI 批量导入。

## 功能

- **多账号管理**：任意数量的 TOTP 账号，各自独立 secret / 位数 / 周期
- **批量导入**：支持三种格式混排自动识别、自动去重
  - `otpauth://totp/...` URI（每行一个）
  - 纯 base32 secret（≥16 字符）
  - `名称: secret`（冒号分隔）
- **站点匹配自动填充**：账号绑定 URL/域名后，登录页自动检测验证码输入框并填入
  - 通用检测：`autocomplete=one-time-code`、`name=code/otp/totp` 等标准字段 + placeholder 关键词 + 6-8 位短数字框
  - **站点规则可配置**：登录页字段不标准时，通过油猴菜单「添加站点规则」配置「域名 → 字段选择器 → 提交按钮」，规则保存在本地（JumpServer 类站点示例：`#mfa-otp input.input-style` + `#submit_button`）
- **悬浮面板**：仅在页面存在验证码输入框时显示（登录后自动隐藏）；实时验证码 + 倒计时，一键复制 / 填入 / 增删账号
- **备份导出**：一键导出全部账号为 otpauth URI 复制到剪贴板
- 账号 URL 支持逗号分隔多域名（如 `vpn.example.com, jumpserver.example.com`）
- 自动填充 / 自动提交可独立开关；http 内网站点可用（含复制兜底）

## 安装

1. 安装 [Tampermonkey](https://www.tampermonkey.net/) 浏览器扩展
2. 打开 [`multi-2fa-autofill.user.js`](multi-2fa-autofill.user.js) 并查看 Raw 内容
3. 在 Tampermonkey 中确认安装或更新

## 使用

1. 点击浏览器工具栏 Tampermonkey 图标 → 菜单 → **导入 otpauth / secret**
2. 粘贴 TOTP URI 或密钥（每行一个），确认导入
3. 给账号绑定站点：面板「添加」或编辑时填写站点 URL/域名（支持逗号分隔多个），匹配后登录页自动填充
4. 站点字段特殊时：菜单 → **添加站点规则**，配置验证码输入框的 CSS 选择器

## 获取 TOTP 密钥

- 各站点「重新绑定验证器」时显示的二维码 / 密钥文本（微软 Authenticator 无导出，需重新绑定）
- Bitwarden / Vaultwarden 导出的 JSON 中 `login.totp` 字段（即为 `otpauth://` URI）

## 安全说明

- TOTP 密钥保存在 Tampermonkey 本地存储（`GM_setValue`），不会上传、不会写入脚本文件
- 更新脚本不影响已保存的账号
- 导出备份含全部明文密钥，请妥善保管，勿泄露
- 建议仅用于个人可信设备的浏览器环境
