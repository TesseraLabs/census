# Census 文档

**Unix 访问对象的声明式配置器。** Census 使设备的访问层——角色账户、组、
`sudoers.d`、限制、文件 ACL——与声明保持一致。幂等、fail-safe、位于认证路径之外。

语言：[English](../en/index.md) · [Русский](../ru/index.md) · **中文**

## 按角色

### 运维 —— 在设备上部署 Census

1. [getting-started.md](getting-started.md) —— 安装、配置、首次 `apply` 与运维
   （计划性 reconcile、漂移检查、teardown）。从这里开始。
2. [toml-reference.md](toml-reference.md) —— 完整的 TOML 格式：声明与角色切片的每个
   字段，以及 `plan --diff` 预览模式。

### 目录 / 包作者 —— 扩展权限目录

1. [`catalog-authoring.md`](../catalog-authoring.md) —— 编写目录权限与按 OS 分层
   *（俄文）*。
2. [`authoring-packages.md`](../authoring-packages.md) —— 编写 add-on 包与精选的
   `<app>.{observe|operate|admin}` 层 *（俄文）*。

## 参考

- `../../README.md` —— 产品模型、安全属性、完整 CLI 参考与 open-core 边界。
- `../../contract/*.schema.json` —— 权威的机器可读 schema（声明、role-store、目录权限、
  framework、受管注册表）。
- `../../examples/` —— 完整可运行的 role-store + 声明。
