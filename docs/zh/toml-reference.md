# Census TOML 格式参考

逐文件、逐字段地完整说明 Census 读取的每一个 TOML 文件。它是
[`getting-started.md`](getting-started.md)（展示常见情形）的补充，给出完整面：每个
字段、其类型、是否必填、默认值与含义。

Census 读取以下几类文件：

| 文件 | 由谁编写 | 严格性 | 本文 |
|---|---|---|---|
| **声明**（`declaration.toml`） | 运维 / 控制平面 | 严格（拒绝未知键） | §1 |
| **角色切片**（role-store `<role>.toml`） | 运维 / Tessera | 顶层宽松；`[[payload.files]]` 严格 | §2 |
| **目录权限**（`share/permissions/**/*.toml`） | 目录作者 | 严格 | §3（概要 + 链接） |
| **Framework**（`frameworks/<fw>/*.toml`） | 合规作者 | 严格 | §4（概要 + 链接） |
| **受管注册表**（`/var/lib/census/managed.toml`） | **仅 Census** | — | §5（请勿编辑） |
| **审计配置**（`/etc/census/exposure.toml`） | 运维 | 严格 | §6（可选） |

权威的、机器可读的 schema 位于 `contract/*.schema.json`（由解析器生成，golden 锁定）。
本文是其散文镜像；如有不一致，以 schema 为准。

> **约定。**「必填」指缺少它解析就会失败。「严格」意为 `deny_unknown_fields`——键名拼错
> 即为错误（fail-closed），而非被悄悄忽略。「宽松」意为未知键被跳过（一种由其他工具共同
> 拥有的格式）。

---

## 1. 声明 —— `declaration.toml`

声明是设备的期望状态：应存在哪些角色账户与组。它被**严格**解析——任何位置的未知键都是
错误。

### 1.1 顶层

| 键 | 类型 | 必填 | 含义 |
|---|---|---|---|
| `schema` | 整数 | 是 | 声明的**解析器格式版本**。当前为 `1`。Census **最先**检查它，先于任何其他校验，并拒绝其 `schema` 超出本构建所支持范围的声明（fail-closed，不做任何变更）——见 §1.1.1。 |
| `version` | 整数 | 是 | 声明内容的**单调 anti-rollback 计数器**（保护签名不被 replay）——*不是*格式版本。仅在 managed/signed 模式下强制；在 `--trust-fs` 下**不检查**。每次新签名的声明都应递增它。见 §1.1.1。 |
| `role_store` | 路径 | 是 | role-store 目录路径，**相对于 Census 运行的工作目录**解析（或绝对路径）。 |
| `[defaults]` | 表 | 是 | 账户默认属性（§1.2）。 |
| `[[role_account]]` | 表数组 | 否 | 要配置的角色账户（§1.3）。 |
| `[[group]]` | 表数组 | 否 | 独立的组（§1.4）。 |
| `[[role_group]]` | 表数组 | 否 | 将某角色的授权绑定到已声明的组（§1.5）。 |
| `signature` | 字符串（hex） | 仅 managed | 对声明字节的分离式 Ed25519 签名。当声明被集中签名时存在；在 `--trust-fs`（standalone）下**不存在**。不由手工编写——由控制平面添加。 |

#### 1.1.1 `schema` vs `version` —— 两个不同的数字

这两个整数字段看起来相像、容易混淆，但它们回答的是不同的问题：

| 字段 | 回答 | 强制 |
|---|---|---|
| `schema` | *「这是哪种 TOML 格式？」*——解析器格式版本。 | 始终。**最先**检查，先于任何其他字段；`schema` 比本构建所支持的更新 → 拒绝、fail-closed、不做变更。 |
| `version` | *「这份内容有多新？」*——保护签名不被 replay 的单调 anti-rollback 计数器。 | 仅在 managed（签名）模式下；在 `--trust-fs` 下**不**检查。 |

- **`schema`** 关乎文件的*形态*。仅当格式本身发生不兼容变更时才递增它；不理解更新
  `schema` 的构建会干净地停下并给出清晰提示，而非在深处遇到未知键才失败。
- **`version`** 关乎*内容*。**每次新签名的声明**都应递增它，使攻击者无法重放
  （replay）较旧的已签名副本、把设备回退到陈旧的访问。在 standalone（`--trust-fs`）模式
  下没有签名可重放，因此 `version` 被记录但不强制。

二者独立变动：重新签发设备的访问会递增 `version` 而 `schema` 不变；迁移文件格式会递增
`schema` 而 `version` 不受影响。把它们合并成一个字段，要么会在格式升级时造成误判式的
rollback 拒绝，要么会在 schema 重构时留下 replay 防护的漏洞。

### 1.2 `[defaults]`

应用于每个角色账户，除非该账户覆盖。严格。

| 键 | 类型 | 必填 | 含义 |
|---|---|---|---|
| `uid_range` | `[整数, 整数]` | 是 | 闭区间 `[low, high]` UID 窗口。每个账户的 `uid` 必须落在其中。 |
| `shell` | 字符串 | 是 | 默认登录 shell（如 `/bin/bash`）。 |
| `home_base` | 路径 | 是 | 角色账户家目录的父目录；账户家目录默认为 `<home_base>/<role>`。 |

```toml
[defaults]
uid_range = [9000, 9999]
shell     = "/bin/bash"
home_base = "/var/lib/census/home"
```

### 1.3 `[[role_account]]`

每个角色账户一条记录。严格。账户是**两种互斥类型**之一，由其身份来源区分：

- **Created（创建）** —— 携带显式 `uid`。Census 以该全设备群稳定的 UID 创建 Unix 用户
  （以角色命名）。这是常规情形。
- **Adopted（接管）** —— 携带 `user`（一个**已存在**的 OS 账户名）与 `adopt = true`，
  且**不得**携带 `uid`。Census 把角色的授权绑定到该既有账户，绝不运行
  `useradd`/`userdel`——它不会给自己未创建的用户分配 UID。

`uid` 与 `user` 互斥；同时声明二者会被拒绝。

| 键 | 类型 | 必填 | 默认 | 含义 |
|---|---|---|---|---|
| `role` | 字符串 | 是 | — | 角色名；必须匹配 role-store 中的切片（§2）。 |
| `uid` | 整数 | **Created**：是 | — | 显式的、设备群稳定的 UID。必须在 `uid_range` 内。缺失 ⇒ 该账户必须是 Adopted。 |
| `user` | 字符串 | **Adopted**：是 | — | 要接管的既有 OS 用户名。与 `uid` 互斥；需要 `adopt = true`。 |
| `adopt` | bool | 否 | `false` | `true` 标记账户为 Adopted（需要 `user`，禁止 `uid`）。`false` 为以 `uid` 为键的 Created 账户。 |
| `shell` | 字符串 | 否 | `[defaults].shell` | 该账户的登录 shell 覆盖。 |
| `home` | 路径 | 否 | `<home_base>/<role>` | 该账户的家目录覆盖。 |

```toml
# Created 账户（常规情形）
[[role_account]]
role = "oper"
uid  = 9001

# Adopted 账户 —— 把角色的授权绑定到既有的 `svc` 用户
[[role_account]]
role  = "legacy-svc"
user  = "svc"
adopt = true
```

> **Created** 角色账户在创建时带**锁定密码**且**无 `authorized_keys`**——其唯一入口是
> 认证器的 PAM 服务。这些不是声明字段；Census 在创建时强制施加。**Adopted** 账户的
> 凭据状态保持原样（Census 绝不对其运行 `useradd`/`userdel`）。

### 1.4 `[[group]]`

Census 应拥有的独立组。严格。

| 键 | 类型 | 必填 | 默认 | 含义 |
|---|---|---|---|---|
| `name` | 字符串 | 是 | — | 组名。 |
| `gid` | 整数 | 否 | 自动 | 固定 GID。若该 GID 已属于*另一个*组，`apply` 拒绝——它绝不重新编号。 |
| `adopt` | bool | 否 | `false` | 接管同名的既有组而非创建。 |
| `members` | 字符串数组 | 否 | `[]` | 成员账户名。 |

```toml
[[group]]
name    = "kiosk-ops"
members = ["oper"]
```

### 1.5 `[[role_group]]`

一种授权绑定：把**某角色已解析的权限**附加到一个组，使组内每个成员都继承它们
（多对一——多个角色可绑定到同一个组）。严格。

| 键 | 类型 | 必填 | 含义 |
|---|---|---|---|
| `role` | 字符串 | 是 | 其授权被绑定的角色。 |
| `group` | 字符串 | 是 | 目标组——**必须**命名同一声明中声明的 `[[group]]`（§1.4）。 |

```toml
[[group]]
name = "kiosk-ops"

[[role_group]]
role  = "oper"
group = "kiosk-ops"
```

---

## 2. 角色切片 —— `<role-store>/<role>.toml`

每个角色一个文件。**顶层宽松**——Census 只读取它消费的键，忽略其余（角色 schema 由
Tessera 共同拥有，它添加 Census 不需要的适配字段）。Census 作用的一切都在 `[payload]`
之下。

### 2.1 顶层（角色级）

| 键 | 类型 | Census 使用 | 含义 |
|---|---|---|---|
| `role` | 字符串 | 信息性 | 角色名（应与声明的 `role` 匹配）。 |
| `version` | 整数 | 信息性 | 切片 schema 版本。 |
| `os` | 字符串 | 信息性 | 目标 OS 系列（如 `linux`）。 |
| `name` | 字符串 | 信息性 | 人类可读的角色标题。 |
| `level` | 整数 | 信息性 | 角色层级（由 Tessera 拥有）。 |
| `[payload]` | 表 | **是** | Census 物化的访问（§2.2）。 |

未知的顶层键被忽略（宽松）。

### 2.2 `[payload]`

所有字段可选；宽松（未知键被忽略）。原始原语（`groups`、`sudo`、`sudo_role`、
`limits`、`files`）是一个**逃生舱（escape hatch）**，它与 `permissions` 的展开
**取并集**——可用其一，或两者皆用。

| 键 | 类型 | 含义 |
|---|---|---|
| `permissions` | 数组 | 针对目录展开的权限引用（§2.3）。授予访问的常规方式。 |
| `groups` | 字符串数组 | 直接添加的原始附加组（逃生舱——绕过目录）。 |
| `sudo` | 字符串数组 | 直接携带的原始内联 `sudo` 命令规则（逃生舱——绕过目录）。仅限字面量绝对命令路径；见 §2.7。 |
| `sudo_role` | 字符串 | 直接携带的原始 sudo 角色名（逃生舱）。 |
| `[payload.limits]` | 表 | 资源限制（§2.4）。 |
| `[[payload.files]]` | 表数组 | 原始的内联文件访问授权（§2.5）。 |

```toml
role    = "oper"
version = 1
os      = "linux"
name    = "设备操作员"
level   = 3

[payload]
permissions = ["service-restart", "log-read", { id = "service-control", units = "nginx" }, "nginx.operate"]
groups      = ["video"]                 # 逃生舱，取并集
sudo        = ["/usr/sbin/reboot"]      # 逃生舱，原始 sudo 命令（§2.7）
sudo_role   = "operations"              # 逃生舱

[payload.limits]
nofile = 8192

[[payload.files]]
path      = "/var/lib/app/state"
access    = "rw"
recursive = true
```

### 2.3 `permissions` —— 三种形式

`permissions` 的每个元素是下列之一：

1. **裸 id** —— 命名 leaf、bundle 或 package 的字符串：
   ```toml
   permissions = ["log-read", "network-config", "nginx.operate"]
   ```
2. **参数化** —— 带必填 `id` 加参数的表，参数填充权限的 `{placeholder}` 模板（如
   `service-*` 权限适用的 unit）。列表参数展开为每元素一条规则：
   ```toml
   permissions = [
     { id = "service-control", units = "nginx" },
     { id = "service-observe", units = ["nginx", "mosquitto"] },
   ]
   ```
   表形式是**宽松**的：`id` 以外的键被捕获为参数，因此目录记录未使用的参数名只是惰性
   （而非错误）。

**leaf** 是单一能力；**bundle** 聚合其他（递归解析，其风险等级 = 各成员的最大值）；
**package** 是精选的 `<app>.{observe|operate|admin}` 层。完整权限列表见 §3 与目录本身。

### 2.4 `[payload.limits]`

| 键 | 类型 | 含义 |
|---|---|---|
| `nofile` | 整数 | `RLIMIT_NOFILE`（最大打开文件数）。 |
| `nproc` | 整数 | `RLIMIT_NPROC`（最大进程数）。 |

### 2.5 `[[payload.files]]`

内联文件访问授权，与目录的 `[[file]]` 授权同形。与 payload 其余部分不同，此块为
**严格**（`deny_unknown_fields`）：角色的文件授权以 root 经 `setfacl` 物化，因此拼错的
键会 fail-closed。

| 键 | 类型 | 必填 | 默认 | 含义 |
|---|---|---|---|---|
| `path` | 字符串 | 是 | — | 指向目录、文件或 glob 的**绝对**路径。必须是**字面量**——角色文件授权中拒绝 placeholder/模板（不得有 `{…}`）。 |
| `access` | 字符串 | 是 | — | 访问位——见 §2.6。 |
| `recursive` | bool | 否 | `false` | 对目录：递归应用**并**设置 default-ACL，使新文件继承该访问。 |

> **目录 vs 单个文件。** 目录授权（`recursive = true`）可抵御重写，由始终可用的 ACL
> 后端强制执行。对**单个文件**的授权需要 per-file 后端；在没有它的系统上，`apply` 会
> 拒绝它（原子地——什么都不应用）。优先使用目录授权。

### 2.6 `access` 取值

`access` 是一组位：read（`r`）、write（`w`）、execute（`x`）、traverse（`X`，目录搜索
/ 条件执行）。两个 legacy 别名覆盖常见情形，其余有规范的紧凑字符串：

| 取值 | 位 | 用途 |
|---|---|---|
| `"ro"` | `{read, traverse}`（`r-X`） | 对目录树只读 |
| `"rw"` | `{read, write, traverse}`（`rwX`） | 对目录树读写 |
| 规范紧凑字符串 | `r` `w` `x` `X` 的任意组合 | 精确控制 |

多数授权需要的正是 `"ro"` 与 `"rw"`。

### 2.7 `payload.sudo` —— 原始 sudo 命令（逃生舱）

`[payload]` 下的 `sudo` 是 `[[payload.files]]` 的命令级孪生：一份**直接**携带进角色的
原始 `sudo` 命令规则列表，与角色 `permissions` 的展开**取并集**——与目录权限的 `sudo`
字段同途。用于尚无对应目录权限的命令。

```toml
[payload]
sudo = ["/usr/sbin/reboot", "/usr/bin/systemctl"]
```

约束——在向 `sudoers` 写入任何内容**之前**校验，违反则 fail-closed：

- **仅限字面量绝对命令路径**——每个元素必须以 `/` 开头。
- **不得有参数、不得有 `{placeholder}` 模板。** 带 confinement 的参数化（由 `[params]`
  约束护住的 `{unit}`）仍是 catalog-id 的专属——内联参数无从约束，故被拒绝。
- **可打印 ASCII，不得有 shell 元字符**（`; | & $ < >` 等）——一律拒绝，以免某个值把第二
  条命令夹带进 sudoers 行。

每个元素以 **root** 物化进 `sudoers.d/census-<role>`，因此是一次真正的提权授予。由于它绕过
精选目录，它**不带风险标签**——因此 `census show` 与 `census compile --lint` 会把内联
`payload.sudo`（如同 `[[payload.files]]`）标记为 **raw / unlabeled escalation-capable**，
使审阅者总能看到它。有对应目录权限时优先使用之；仅在有意使用逃生舱时才动用 `payload.sudo`。

---

## 3. 目录权限文件（概要）

`share/permissions/<layer>/*.toml` 下的目录文件定义角色引用的权限。其编写在
[`catalog-authoring.md`](../catalog-authoring.md) 与
[`authoring-packages.md`](../authoring-packages.md)（均为俄文）中详述；形状简述如下：

| 键 | 类型 | 含义 |
|---|---|---|
| `id` | 字符串 | 权限 id（包为点分，如 `nginx.operate`）。 |
| `risk` | 字符串 | `contained` 或 `escalation-capable`（bundle 的 = 成员最大值）。 |
| `category` | 字符串 | 域分组（如 `network`、`app`、`os-config`）。 |
| `sudo` | 字符串数组 | 绝对 `sudo` 规则（可携带 `{placeholder}` 模板）。 |
| `groups` | 字符串数组 | 授予的附加组。 |
| `[limits]` | 表 | `nofile` / `nproc`。 |
| `[[file]]` | 表数组 | 文件访问授权（与 §2.5 同形；目录授权**可**使用 `{placeholder}` 模板）。 |
| `includes` | 数组 | 本权限聚合的其他权限 id（bundle）；表元素 `{ id, <bindings> }` 绑定成员参数。 |
| `include_categories` | 字符串数组 | 聚合所命名类别中的每个权限。 |
| `[params.<name>]` | 表 | 参数护栏（`kind = token | path | enum | segment`，带 `allow_prefix` / values），约束某个 `{placeholder}`。 |

按 OS 分层：权限沿 `linux → linux-<distro> → linux-<distro>-<version>` 解析；某层可
`replace` 或 `append` 基础层的字段。人类文本（`title` / `summary` / `risk_note`）位于
独立的 `l10n/<locale>/` 树中，以 `[<id>]` 为键，而非权限文件内。

权威 schema：`contract/catalog-permission.schema.json`。

---

## 4. Framework 文件（概要）

建议性（advisory）合规交叉引用。Framework 位于 `frameworks/<fw>/`：

- `framework.toml` —— 清单（`dimension = flat | os-layered`、版本、provides）。
- `mappings/*.toml` —— 以权限 id 为键；每个链接带**极性**：`satisfies`（满足该控制——
  覆盖率唯一计入的极性）、`risk`（削弱它）、`related`（中性）。
- `controls.toml`（可选）—— 控制列表；`owned` 标志标记 Census 实际覆盖的控制（使
  `framework coverage` 能报告缺口）。

它是**只读且建议性**的——绝不参与 `compile`/授权/`apply`，因此被篡改的 mapping 只能误标
覆盖率，绝不能提权。权威 schema：`contract/framework.schema.json`。见 README 的
「Compliance frameworks」节。

---

## 5. 受管注册表 —— `/var/lib/census/managed.toml`

仅 root 可读的记录，记载 Census 配置过的内容（账户、组、各自附带的授权、已应用的声明
版本）。**该文件由 Census 拥有——请勿手工编辑。** Census 借它得知哪些是*它的*、可供调和
或拆除，因此编辑它可能使真实 OS 对象成为孤儿，或令 Census 触碰它未创建的东西。用
`census status` 只读查看。权威 schema：`contract/managed-registry.schema.json`。

---

## 6. 审计配置 —— `/etc/census/exposure.toml`

只读[暴露审计](audit.md)（`census audit fs` / `census audit expose`）的可选配置。被**严格**
解析（`deny_unknown_fields`）。该文件可选，且每个键都可选：文件不存在、或某个键缺失，会回退
到内置默认值。一个**存在却格式错误**的文件是一个硬错误——绝不是无声的默认（一个配置错误的
安全工具必须大声失败，而不是看似健康却在扫描错误的目标）。用 `--config` 传入非默认路径。

| 键 | 类型 | 必填 | 默认 | 含义 |
|---|---|---|---|---|
| `scan_roots` | 路径数组 | 否 | `["/etc","/var","/opt","/usr/local","/srv","/home","/root"]` | 默认扫描覆盖的目录树。每一项**必须是绝对路径**；**空列表会被拒绝**（一次什么都不扫却报告「一切正常」的扫描是个陷阱）。可由每次运行的 `--root`/`--full` 覆盖。 |
| `secret_globs` | 字符串数组 | 否 | `["/etc/shadow*","**/*.key","**/*.pem","**/id_rsa*","**/.env*","**/*credentials*"]` | 把对象标记为 **secret 类**的 glob（因此一个被 `other` 可读的匹配项即为 `leak`）。每个模式至多包含**一个 `**`**（匹配器会在 `**` 处回溯；两个会在 `--full` 扫描上呈指数级）——含更多的模式在加载时被拒绝。 |
| `broad_groups` | 字符串数组 | 否 | `["adm","wheel","sudo","staff","users"]` | 在「宽组可写」这一维度上被视为「宽」的组**名**。按从 `/etc/group` 解析出的组真实名匹配，因此一台重新编号 gid 的主机仍会被捕获。 |

```toml
# /etc/census/exposure.toml
scan_roots   = ["/etc", "/var", "/opt", "/usr/local", "/srv", "/home", "/root"]
secret_globs = ["/etc/shadow*", "**/*.key", "**/*.pem", "**/id_rsa*", "**/.env*", "**/*credentials*"]
broad_groups = ["adm", "wheel", "sudo", "staff", "users"]
```

> 默认的 `**/*.pem` glob 也会匹配公开证书（如 `/etc/ssl/certs`），它们按设计就是全局可读的，
> 会以低信号的 `secret` 发现浮现——若不需要这种噪声，可收窄 `secret_globs`。见
> [audit.md §6](audit.md#6-配置--exposuretoml)。

---

## 7. 预览变更 —— diff 模式

`census plan` 打印高层的 create/update/delete 动作。加上 `--diff` 即可看到每个变更将写入
的**具体产物**，以统一 diff 呈现——当前受管状态对已解析目标：

```sh
census plan --declaration declaration.toml --additional-catalog-dir /opt/census/share/permissions --diff
```

`plan --diff` 按每个变更的账户显示：

- 将写入的 **`sudoers` 片段**（含 run-as 规范）及其**目标文件路径**
  （`/etc/sudoers.d/census-<role>`）；
- **文件访问 ACL 授权增量**——新增或移除了哪些路径授权。

它是**只读**的：不修改文件系统，不需要 root。用它在运行 `apply` 之前精确审阅它将改动
什么——尤其在编辑角色权限之后，以确认产生的 sudo 行与 ACL 正是你所期望的。

---

## 延伸阅读

- [`getting-started.md`](getting-started.md) —— 安装、配置、首次 apply、运维。
- [`catalog-authoring.md`](../catalog-authoring.md) —— 编写目录权限与按 OS 分层（俄文）。
- [`authoring-packages.md`](../authoring-packages.md) —— 编写 add-on 包与精选应用层（俄文）。
- `contract/*.schema.json` —— 权威的机器可读 schema。
