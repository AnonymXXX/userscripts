# 油猴脚本集（UserScripts）

个人 Tampermonkey 脚本集合，集中管理、统一安装与更新。每个脚本一个独立目录，目录内包含脚本文件与使用说明。

## 脚本列表

| 脚本 | 目录 | 功能 |
| --- | --- | --- |
| Multi 2FA Autofill | [`multi-2fa-autofill/`](multi-2fa-autofill/) | 多账号 TOTP 管理器：otpauth URI 批量导入、站点匹配自动填充、悬浮面板一键复制，仅在页面存在验证码输入框时显示 |
| 三角洲行动地图助手 | [`delta-force-map-helper/`](delta-force-map-helper/) | 三角洲行动官方地图 AZ3 出生点/大保险箱点位辅助 |

## 安装

1. 安装 [Tampermonkey](https://www.tampermonkey.net/) 浏览器扩展。
2. 进入对应脚本目录，打开 `.user.js` 文件并查看 Raw 内容，在 Tampermonkey 中确认安装或更新。
3. 更新脚本时，油猴会按脚本内的 `@name` 自动匹配覆盖旧版本。

## 新增脚本

1. 新建 `<脚本名>/` 目录
2. 将 `.user.js` 放入目录
3. 在目录内编写 `README.md`（功能、安装、使用、注意事项）
4. 在本文件「脚本列表」表格中补充一行
