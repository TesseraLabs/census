# 暴露审计 —— 主体已能触及什么

`census audit` 是对文件系统*实际*权限状态的**只读**审视。它回答配置无法回答的问题：
给定一台设备上的访问对象——不是 Census 声明的那些，而是磁盘上已经存在的一切——
**某个主体真正能读、能写的，超出最小权限本意的范围有多大？**

这与 `apply` 相反。`apply` 向前授予访问（角色账户、组、`sudoers.d`、文件 ACL）；
`audit` 则审视设备*现状*，揭示那些悄悄削弱受限账户的 ambient 过度权限：一个全局可写的
`cron` 假脱机目录、一份全局可读的密钥、一个服务账户可编辑的 `sudoers.d` drop-in。你把某个
账户做成受限的，但一个全局可写的文件仍让它得以提权——`audit` 正是发现此类问题的手段。

`audit` **绝不改动任何东西**。和 `doctor` 一样，它只读。它不会、也不能对文件 `chmod` 或
`setfacl`——它报告问题并告诉你修复方法。

两种模式，同一引擎：

| 命令 | 它回答的问题 |
|---|---|
| `census audit fs` | *这台设备上存在哪些危险的权限类别？*（与主体无关的态势图） |
| `census audit expose --principal <name\|uid>` | *这个具体账户实际能触及什么——超出它被授予的范围？* |

> **以 root 运行才能看到完整画面。** 审计读取文件模式、属主与 POSIX ACL；要判断
> secret 类文件（如 `/etc/shadow`）的暴露程度，读取它们需要 root。请在 `sudo` 下运行以获得
> 完整覆盖——它是只读的，因此以 root 运行是安全的。

---

## 1. `audit fs` —— 设备态势图

`audit fs` 遍历在范围内的目录树，枚举危险的权限类别，与任何主体无关：

- 敏感树（cron、`sudoers.d`、systemd unit、配置、`PATH` 二进制）中的**全局可写**对象；
- **setuid/setgid 清单**——每一个 setuid/setgid 二进制，其中*同时*全局可写的会被标为
  critical；
- **全局可读的密钥**——`other` 能读取的 key/credential/shadow 类文件；
- **宽组可写**对象——可被某个宽泛的组（`adm`、`wheel`、`sudo`、`staff`、`users`）写入。

```sh
sudo census audit fs --root /etc --root /var/spool
#   audit fs: 1 finding(s)
#   high   leak  secret  /etc/ssl/certs/ssl-cert-snakeoil.pem (access r--, via other_bits, fix ambient)
#       — remove world read of a secret manually: `chmod 640 /etc/ssl/certs/ssl-cert-snakeoil.pem`
```

每条发现携带：**路径**、有效**访问**（`rwx`）、访问的**获取方式**（`via`——`other_bits`、
`group:<g>`、`acl_user:<u>`……）、对象**类别（class）**、**风险**（`escalation` / `leak` /
`tamper`）、一个派生的**严重度**、**remediation class**（§4），以及一条具体的**修复提示**。

---

## 2. `audit expose` —— 单个账户能触及什么

`audit expose` 把同一次扫描按单个主体切片。它解析账户身份——UID 加主组与附加组——并
**针对该主体**对每个在范围内的对象求值 POSIX 访问检查，然后只报告该账户实际能触及的内容。

```sh
sudo census audit expose --principal daemon --root /etc --root /var/spool
#   audit expose: principal daemon (unmanaged)
#   note: verdict is DAC-only (mode, owner, POSIX ACL) and is an upper bound:
#         MAC layers (SELinux, AppArmor, PARSEC) may restrict actual access further
#   1 finding(s)
#   high   leak  secret  /etc/ssl/certs/ssl-cert-snakeoil.pem (access r--, via other_bits, fix ambient) — …
```

主体由**登录名或数字 UID** 指定。身份**仅**从**本地**的 `/etc/passwd` 与 `/etc/group`
解析——NSS/LDAP 提供的组成员关系*不*被查询（一项告知性的局限：在目录后端的主机上，
基于组的可达性可能被低估）。一个在 passwd 中没有对应条目的裸 UID 仍可被审计，
按无任何组成员关系的原始可达性来计算。

### 2.1 可达性是严谨的 —— 不会因父目录关闭而产生误报

只有当**每一级祖先目录都授予搜索（`x`）**时，文件才算被某主体「可达」。一个模式为
`0777` 的文件若位于 root 所属、模式为 `0700` 的目录之后，对非属主而言是**不可达**的，
也*不会*被报告——这正是 `find -perm` 那种朴素做法会产生的误报。访问检查本身遵循 POSIX ACL
算法（owner → named-user → 带 mask 的 group-class → other），尊重 ACL mask 以及
「匹配但被拒不会回退到 other」这条规则。

### 2.2 裁决仅基于 DAC —— 一个诚实的上界

`audit` 只求值**自主**访问控制（DAC）：模式位、属主与 POSIX ACL。它**不**建模强制访问控制
（SELinux、AppArmor，或 Astra 的 PARSEC 强制完整性）。MAC 层可能进一步限制访问，因此裁决
是一个**上界**——「在 DAC 下可达」。每份 `expose` 报告都会声明这一点。

### 2.3 关键过滤器 —— 对受管账户只显示*超额*部分

当主体是 **Census 受管的角色账户**时，`expose` 会减去它的**预期基线**——它的家目录加上目录
（catalog）授予它的路径——只报告它在该意图*之外*拥有的访问。你声明该账户应能触及
`/etc/ssh`；如果它*还*能写 `/var/spool/cron`，那么只有 cron 这条发现会保留。对于 Census 不
管理的账户，没有可减去的基线，因此显示原始可达性。

这正是 `expose` 之所以是 Census 特有、而非通用权限扫描器的原因：它知道账户*本应*拥有什么，
并把差额展示给你。

---

## 3. 风险、严重度与对象类别

每个在范围内的对象按一张 glob 表（以及 setuid/setgid 位）分类：

| 类别 | 示例 |
|---|---|
| `cron` | `/var/spool/cron/**`、`/etc/cron*/**`、`/etc/crontab` |
| `systemd-unit` | `/etc/systemd/**`、`/lib/systemd/system/**` |
| `sudoers` | `/etc/sudoers`、`/etc/sudoers.d/**` |
| `path-binary` | `/usr/bin/**`、`/bin/**`、`/usr/local/bin/**`、`/sbin/**` |
| `secret` | `/etc/shadow*`、`**/*.key`、`**/*.pem`、`**/id_rsa*`、`**/.env*`、`**/*credentials*` |
| `config` | 安全相关的 `/etc` 配置 |
| `setuid-binary` | 任意 setuid/setgid 可执行文件 |
| `generic` | 其余一切 |

风险与严重度被确定性地派生：

- **写入** cron / sudoers / systemd-unit / `PATH` 二进制 / setuid 二进制 → `escalation`，
  **高**；
- **读取** secret → `leak`，**高**；
- **写入**配置文件 → `tamper`，**中**；
- 全局可写的 generic 对象 → **低**；
- 读取非 secret 文件*不*构成发现。

当任意发现达到或超过**高**严重度时，`audit` 以**非零**退出（与 `doctor` 相同的约定），
因此可用于把守 CI 或监控检查；一次干净的扫描（或仅有低于阈值的发现）以 `0` 退出。

---

## 4. remediation class —— Census 对自己能修什么是诚实的

每条发现都被标注一个 **remediation class**，告诉你*谁*来修它：

- **`ambient`** —— 访问来自 Census **不**拥有的对象：一个全局可写的外来目录、一份全局可读的
  密钥、一个外来组。Census **无法**移除它——声明只配置 Census *自己的*对象，它不会触碰某个
  文件的基础模式或某个外来 ACL。提示是一条**手工**命令（`chmod o-w …`、`chmod 640 …`、
  `setfacl -x …`）；Census 绝不声称会替你修复。
- **`in-model`** —— 访问来自 Census **拥有**的对象：在某个 Census 受管组中的成员关系，或
  账户自身某条比所需更宽的文件访问授权。这里的修复*就是*一次声明变更，提示也会这样说
  （「收窄该声明」）。

这一区分化解了那个显而易见的反对意见——*「一份声明无法撤销每个文件上的全局可写。」*
没错：它做不到，`audit` 也不假装做得到。对于 ambient 过度权限，它的职责是**精确地报告问题**
——哪个主体、哪条路径、为何存在该访问，以及关闭它的手工命令。

> **报告本身是一份敏感产物。** 它是一张设备弱点地图。输出只携带元数据——路径、模式、类别
> ——并且**绝不包含** secret 文件的**内容**，但请把报告本身当作机密：不要把它粘贴到公开频道
> 或不受限的日志里。

---

## 5. 范围、输出与标志

```
census audit fs      [--root <PATH>]… [--full] [--format text|json]
                     [--config <PATH>] [--managed <PATH>]
census audit expose  --principal <name|uid>
                     [--root <PATH>]… [--full] [--format text|json]
                     [--config <PATH>] [--managed <PATH>]
```

| 标志 | 含义 |
|---|---|
| `--root <PATH>` | 扫描根（可重复）。与 `--full` 冲突。必须是**绝对**路径。 |
| `--full` | 从 `/` 遍历整个文件系统（仍跳过伪文件系统）。 |
| `--principal <name\|uid>` | （仅 `expose`）要求值的账户。 |
| `--format text\|json` | 输出格式。`text`（默认）人类可读；`json` 是输出到 stdout 的稳定、schema 锁定的契约。 |
| `--config <PATH>` | 审计配置（默认 `/etc/census/exposure.toml`）；文件不存在 ⇒ 使用内置默认值。 |
| `--managed <PATH>` | 受管注册表（默认 `/var/lib/census/managed.toml`），用于受管账户基线。 |

**默认范围**是一组精选的安全相关目录树（`/etc`、`/var`、`/opt`、`/usr/local`、`/srv`、
`/home`、`/root`）。伪文件系统（`/proc`、`/sys`、`/dev`、`/run`）与**网络挂载**始终被跳过
——包括在 `--full` 下——任何被跳过的挂载都会在一条通知中报告，因此覆盖范围绝不会被无声地
削减。一次扫描**不会隐式地跨越到另一个本地卷**：本地子挂载（独立的 `/var/log` 或 `/home`
分区）*会*被深入；网络文件系统（NFS、CIFS……）则不会。

当在交互式终端上运行且**未给** `--root`/`--full` 时，`audit` 会给出一个范围提示
（安全相关 / 完整 / 自定义根）。非交互式运行（CI、管道）绝不会因该提示而阻塞——它会无声地
使用默认范围。诊断信息与提示走 **stderr**，因此 `--format json` 让 stdout 保持干净、可解析。

JSON 输出由 golden schema（`contract/exposure-report.schema.json`）锁定。

---

## 6. 配置 —— `exposure.toml`

扫描范围与分类器是可配置的。该文件被**严格解析**（`deny_unknown_fields`）；文件不存在或某个键
缺失会回退到内置默认值，但一个存在却格式错误的文件是一个诚实的错误（绝不是无声的默认）。

```toml
# /etc/census/exposure.toml —— 所有键可选；缺失 ⇒ 内置默认值

# 默认扫描覆盖的目录树。必须是绝对路径；空列表会被拒绝
#（一个什么都不扫却报告「一切正常」的安全工具是个陷阱）。
scan_roots   = ["/etc", "/var", "/opt", "/usr/local", "/srv", "/home", "/root"]

# 把对象标记为 secret 类的 glob。每个模式至多包含一个 `**`
#（匹配器会在 `**` 处回溯；多个会在 --full 扫描上呈指数级）。
secret_globs = ["/etc/shadow*", "**/*.key", "**/*.pem", "**/id_rsa*", "**/.env*", "**/*credentials*"]

# 在「宽组可写」这一维度上被视为「宽」的组名。按从 /etc/group 解析出的组真实名匹配
#（因此被重新编号 gid 的组仍会被捕获）。
broad_groups = ["adm", "wheel", "sudo", "staff", "users"]
```

> **调优说明。** 默认的 `**/*.pem` glob 也会匹配*公开*证书（如 `/etc/ssl/certs`），这些
> 证书按设计就是全局可读的——它们会以低信号的 `secret` 发现浮现。若这种噪声在你的主机上
> 并不需要，可收窄 `secret_globs`，或排除公开证书目录树。

字段表见 [TOML 参考](toml-reference.md)。

---

## 7. 典型用法

```sh
# 对整台设备做态势扫描，输出 JSON 供监控流水线：
sudo census audit fs --full --format json > posture.json

# 这个受限服务账户实际能触及什么？
sudo census audit expose --principal app-svc

# 配置一个新的受限角色后做聚焦检查：
sudo census audit expose --principal kiosk-oper --root /etc --root /var
```

`audit` 是只读的，也不需要声明——把它指向一台设备，它就报告。把 `audit fs` 接入与 `doctor`
相同的监控路径（二者都在出现真正问题时非零退出），并在每次创建或收紧受限账户时运行
`audit expose`，以确认 ambient 文件系统没有给它超出你本意的东西。

---

## 延伸阅读

- [`getting-started.md`](getting-started.md) —— 安装、配置、首次 apply、运维。
- [`toml-reference.md`](toml-reference.md) —— Census 读取的每个 TOML 文件，包括 `exposure.toml`。
- 仓库的 `README.md` —— 产品模型、安全属性与完整 CLI 参考。
</content>
</invoke>
