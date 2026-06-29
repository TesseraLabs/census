# Census 入门

本指南引导运维人员在单台设备上端到端地**安装**、**配置**并**运行** Census：
从放置二进制文件，到应用第一份声明并验证结果，再到长期运维。

Census 是一个*Unix 访问对象的声明式配置器*。你在**声明（declaration）**中描述设备
应具备的访问——存在哪些角色账户、它们拥有哪些组、`sudo` 规则、systemd 限制以及文件
ACL——`census apply` 则使机器达到一致。它是幂等的（若已一致，重复运行不做任何改动）、
原子的（apply 失败会回滚），并且运行在**认证路径之外**——它物化认证器在登录时把守的
OS 对象，但自身不认证任何人。

本指南覆盖 **standalone（独立）**模式（本地受信的声明，无需服务器——open-core 路径）。
末尾的简短章节指向 **managed（受管）**模式（集中签名的声明）。

> 状态：Census 处于预发布阶段（v0.1.0）。下文的命令与路径对应该版本。

---

## 0. 前置条件

Census 运行在 Linux 设备上并修改本地访问数据库，因此需要：

- **root** 才能 apply（它调用 `useradd`/`usermod`/`gpasswd`/`userdel`，写入
  `sudoers.d`，设置 ACL）。只读子命令（`plan`、`compile`、`show`、`status`、
  `doctor`）不需要 root。
- **shadow-utils** —— `useradd`、`usermod`、`gpasswd`、`userdel`（主流发行版均自带）。
- **`sudo`** 及 `visudo` —— Census 在激活前用 `visudo -c` 校验每个片段。
- **`acl`** —— `setfacl`/`getfacl`，**仅当**某个角色授予文件访问权限（对配置/日志
  目录树的 ACL）时才需要。若缺失，使用 `apt-get install acl`（Debian/Ubuntu/Astra）
  安装。文件授权是**目录级**的（目录 ACL 可抵御重写；对单个文件的授权在 apply 时会被
  拒绝，除非安装了 per-file 后端）。
- **systemd** —— 用于 `service-*` 权限（授权 `systemctl …`）以及调度周期性 reconcile
  （§4.1）。

起始目录所支持的发行版系列：**Debian 12**、**Ubuntu 22.04**、**Astra Linux 1.8**。
其他 Linux 也可运行；按 OS 的特定项会回退到系列基础层。

---

## 1. 安装

Census 是单个静态二进制文件。没有守护进程，运行时也无网络依赖。

### 1.1 获取二进制文件

**方式 A —— 从源码构建**（在装有 Rust stable 的构建主机上）：

```sh
git clone https://github.com/TesseraLabs/census.git
cd census
cargo build --release
./target/release/census --version
```

**方式 B —— 为设备交叉编译静态二进制**（推荐用于设备群，例如构建主机与目标不同时）。
`x86_64-unknown-linux-musl` 构建为静态链接（static-pie），无 libc/运行时依赖，因此可在
该架构的任意 glibc/musl Linux 上运行，包括 Astra：

```sh
# 在构建主机上（需要 `cross` + Docker，或 musl 工具链）
cross build --release --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/release/census
#   ... ELF 64-bit LSB pie executable, x86-64, static-pie linked, stripped
```

将生成的 `census` 拷贝到设备上。

### 1.2 放置并赋予可执行权限

将二进制安装到 root 的 `PATH` 目录下（以便计划任务能找到它）：

```sh
sudo install -m 0755 census /usr/local/sbin/census
sudo census --version
```

> **Astra Linux 提示。** 在 Astra 的强制完整性控制（МКЦ）下，非 root 用户无法对刚拷贝
> 的文件执行 `chmod +x`——请使用 `sudo install`（如上）或 `sudo chmod +x`。Astra 的封闭
> 软件环境（ЗПС / digsig）**不会**阻止二进制在具备可执行权限后运行；Census 正常执行。

### 1.3 验证安装

```sh
census --version
census --help          # 列出子命令：plan、apply、doctor、status、
                       #   compile、show、catalog、framework
command -v setfacl     # 仅文件访问权限需要（§0）
```

---

## 2. 配置

一份可用配置包含三样东西：**声明**（要配置哪些账户）、**role-store**（每个角色的含义），
以及**目录（catalog）**（某个权限如何为本发行版展开为 OS 原语）。起始目录随 Census 一同
提供，因此实践中你只需编写声明与 role-store。

仓库中的 `examples/` 目录是一份完整可运行的样例；可将其作为起点拷贝。

### 2.1 声明 —— `/etc/census/declaration.toml`

声明列出本设备应有的角色账户，并将每个绑定到稳定的 UID：

```toml
schema     = 1                # 解析器格式版本——必填（若本 Census 构建不支持则
                              #   fail-closed）
version    = 1                # 单调的内容 anti-rollback 计数器
                              #   （仅在 managed/signed 模式下强制）
role_store = "roles"          # role-store 路径，相对于 census 运行所在的
                              #   工作目录

[defaults]
uid_range = [9000, 9999]      # 角色账户的 UID 必须落在此区间
shell     = "/bin/bash"
home_base = "/var/lib/census/home"

[[role_account]]
role = "oper"                 # 必须匹配 role-store 中的角色切片
uid  = 9001

[[role_account]]
role = "admin"
uid  = 9002
```

- `schema` 是**解析器格式版本**，且为**必填**。Census 会在任何变更之前拒绝它不支持的
  `schema` 的声明——请把 `schema = 1` 这一行复制进你编写的每一个声明。
- `version` 是一个独立的、单调的**声明内容 anti-rollback 计数器**；它仅在 managed
  （签名）模式下强制，在 `--trust-fs` 下不检查。`schema` 与 `version` 的完整区别见
  [TOML 参考](toml-reference.md#11-顶层)。
- `role_store` **相对于 Census 运行的工作目录**解析。要么从包含 `roles/` 的目录运行
  Census，要么使用绝对路径。
- 每个 `uid` 必须落在 `[defaults].uid_range` 内。
- `role` 必须命名 role-store 中存在的切片（§2.2）。

### 2.2 role-store —— 每个角色一个切片

role-store 是一个角色切片目录，每个角色一个 `<role>.toml`。切片命名该角色携带的
**权限（permissions）**：

```toml
# roles/oper.toml
role    = "oper"
version = 1
os      = "linux"
name    = "设备操作员"
level   = 3

[payload]
permissions = [
    "service-restart",                                   # 叶子权限
    "log-read",                                          # 另一个叶子
    { id = "service-control", units = "nginx" },         # 参数化权限
    "nginx.operate",                                     # 精选应用包
]
```

权限是下列之一：

- **叶子（leaf）** —— 单一能力（`log-read`、`network-admin`）；
- **集束（bundle）** —— 聚合其他权限的权限，递归解析
  （`network-config` = `network-diag` + `network-admin` + `firewall-admin` + …）；
- **参数化权限** —— `{ id = "service-control", units = "nginx" }` 绑定该权限适用的
  unit；
- **精选应用包** —— `<app>.{observe|operate|admin}`（如 `nginx.operate`、
  `salt-minion.admin`），常见服务的现成层级。见 §2.4。

要查看现有权限，浏览目录树（§2.3），或用 `census compile` / `census show` 展开某个角色
（§3.2）。

### 2.3 目录与按 OS 定向

**目录**把权限转化为具体的 OS 原语（`groups`、`sudo` 命令、`limits`、文件 ACL）。起始
目录内置于 Census 的 `share/permissions/`。Census 还会在默认目录根
`/usr/share/census/permissions` 与 `/etc/census/permissions.d` 中查找。用
`--additional-catalog-dir` 指向**额外的**目录根（可重复；它追加到默认根之后，id 冲突时靠后
的根优先）：

```sh
census compile oper --additional-catalog-dir /opt/census/share/permissions
```

若只想针对**自己的**目录根运行——一次忽略内置默认根的隔离运行——加上
`--no-default-catalog-dirs`：

```sh
census compile oper \
  --no-default-catalog-dirs \
  --additional-catalog-dir /opt/census/share/permissions
```

`--no-default-catalog-dirs` 会从目录根列表中丢弃两个内置默认根。若在**没有**任何
`--additional-catalog-dir` 时给出，它会使目录根为零——因此 Census 以非零退出码拒绝（它绝不
针对空目录解析）。旧的 `--catalog-dir` 标志——只会追加——已被移除；请改用
`--additional-catalog-dir`。

目录**按 OS 分层**：权限沿链 `linux → linux-debian → linux-debian-12`（以及
`linux-ubuntu`、`linux-astra`）解析，因此同一个 `firewall-admin` 会按情况展开为 `nft`
或 `ufw`。Census 从 `/etc/os-release` **自动检测** OS；在另一台主机上编译时显式覆盖：

```sh
census compile oper --os-target linux-astra-1.8
census compile oper --os-target linux-debian-12
```

> 若确切的版本层不存在（如 `linux-astra-1.8`），Census 会针对最近的基础层
> （`linux-astra`）解析并发出警告——这是预期行为，不是错误。

### 2.4 精选应用包

对于常见服务，目录提供遵循 `<app>.{observe | operate | admin}` 约定的现成权限包：

- **observe** —— 只读：服务状态 + 对应用配置与日志的只读 ACL。始终为 `contained`。
- **operate** —— 生命周期（start/stop/restart）加读取访问；对于守护进程以**非 root**
  运行的服务，`operate` 也可携带可读写配置。
- **admin** —— 可读写配置；当守护进程以 root 运行且其配置可加载代码时为
  `escalation-capable`（重写配置即一条通往 root 的路径）。

包覆盖监控/日志/边缘/自助终端类服务（如 `nginx`、`postgresql`、`redis`、`mosquitto`、
`salt-minion`、`rsyslog`、`docker`、`pcscd`、`chromium` 等）。每个层级都带有**诚实的
风险等级**（`contained` 对 `escalation-capable`）——见 §2.5。

### 2.5 风险等级

每个权限及包层级都被标记：

- **`contained`** —— 该访问本身不能把非 root 主体提升到 root（只读、纯生命周期，或非
  root 守护进程的可读写配置）。
- **`escalation-capable`** —— 该访问提供了通往 root 的路径（`docker` 组、`sudo ALL`，
  或能加载共享对象/运行程序的 root 守护进程的可读写配置——`nginx` 的 `load_module`、
  `salt-minion` 改指 master、`rsyslog` 的 `omprog` 等）。

当通往 root 的路径存在时，Census 绝不把权限伪装成「受限」。用 `census show <role>`
查看任意角色的等级（§3.2）。

### 2.6 standalone 对 managed（信任）

- **standalone**（本指南）：声明通过**文件系统完整性**受信——你在 apply 时传入
  `--trust-fs`。无服务器、无签名。这是 open-core 路径。
- **managed**：声明经 **Ed25519 签名**并带单调防回滚版本，在任何变更前校验。签名声明
  的下发由控制平面（如 Tessera）处理。见 §5。

---

## 3. 首次运行

依次进行 `plan` → `compile`/`show`（检视）→ `apply`（变更）→ 验证。

> 先运行只读命令；`apply` 之前的任何步骤都不会改动系统。

### 3.1 预览计划

`plan` 显示 create/update/delete 动作，且不触碰任何东西：

```sh
cd /etc/census          # 以便 role_store="roles" 能解析
census plan --declaration declaration.toml --additional-catalog-dir /opt/census/share/permissions
#   CREATE oper  (uid 9001, shell /bin/bash)
#   CREATE admin (uid 9002, shell /bin/bash)
```

### 3.2 检视角色的展开

`compile` 把角色展开为带来源（provenance）的扁平 OS 原语（每条 `sudo` 行 / 组 / 文件
授权由哪个权限产生）：

```sh
census compile oper --declaration declaration.toml \
  --additional-catalog-dir /opt/census/share/permissions --os-target linux-astra-1.8 --lint
```

`show` 把同样内容渲染为本地化的「权限 → 原语」树，并标注各自的风险等级（使用
`--lang en|ru|zh`）：

```sh
census show oper --lang zh --additional-catalog-dir /opt/census/share/permissions
```

在 CI 中对 `compile` 使用 `--lint`：任何目录 lint 错误都会使其以非零码退出。

### 3.3 应用

`apply` 执行 **verify → plan → backup → apply**。standalone 模式下传入 `--trust-fs`。
在没有配置其他登录路径的设备上，`apply` 会拒绝继续（防锁死），除非你以
`--i-understand-no-rescue` 确认：

```sh
cd /etc/census
sudo census apply \
  --declaration declaration.toml \
  --additional-catalog-dir /opt/census/share/permissions \
  --trust-fs \
  --i-understand-no-rescue
#   census: create: create oper (uid 9001)
#   census: create: create admin (uid 9002)
#   census: file-access: materialized N grant(s) for oper
#   census: all phases succeeded
#   applied: 2 mutation(s)
```

`apply` 按顺序做的事：

1. **校验**信任（standalone 为文件系统；managed 为签名 + 防回滚）。
2. **快照** `/etc/passwd`、`/etc/shadow`、`/etc/group`、`/etc/gshadow` 及被触碰的
   `sudoers.d/census-*`，以及任何被授权路径的 ACL。某一阶段失败会**原子地**恢复——
   Census 绝不半途而废地应用。
3. 通过 shadow-utils **创建/更新/删除**账户。每个角色账户创建时**密码被锁定**（shadow
   中的 `!`）且**无 `authorized_keys`**——其唯一入口是认证器的 PAM 服务。
4. **写入 `sudoers.d/census-<role>`**，并用 `visudo -c` 校验。角色账户的 sudoers 为
   `NOPASSWD`（账户没有可供提示的密码）。
5. **设置组成员关系与文件 ACL。**

Census 只跟踪自己创建的东西，记录在仅 root 可读的注册表
（`/var/lib/census/managed.toml`）中，绝不触碰外来账户与组。

> **活动会话调和（live-session reconcile）。** 对拥有活动会话的角色账户的破坏性变更会
> 被延后——Census 从 `--sessions-file`（默认 `/run/tessera/sessions.json`；文件不存在
> 表示无活动会话）读取 Tessera 的会话注册表，绝不拆除进行中的会话。

### 3.4 验证结果

```sh
getent passwd oper admin                 # 账户以声明的 UID 存在
sudo cat /etc/sudoers.d/census-oper      # 展开后的 sudo 规则
id oper                                  # 组成员关系
sudo getfacl -p /etc/nginx               # 文件 ACL（若有文件授权）
sudo -l -U oper                          # oper 被授权运行什么
```

也可确认反向查询——哪些权限会授予对某路径的访问：

```sh
census catalog which-grants /etc/nginx --additional-catalog-dir /opt/census/share/permissions --os-target linux-astra-1.8
```

---

## 4. 运维

### 4.1 计划性 reconcile

Census 旨在**周期性**运行，重新断言一致性并拾取声明变更。systemd 定时器是最简单的
调度器：

```ini
# /etc/systemd/system/census-apply.service
[Unit]
Description=Census reconcile
ConditionPathExists=/etc/census/declaration.toml

[Service]
Type=oneshot
WorkingDirectory=/etc/census
ExecStart=/usr/local/sbin/census apply \
  --declaration declaration.toml \
  --additional-catalog-dir /opt/census/share/permissions \
  --trust-fs --i-understand-no-rescue
```

```ini
# /etc/systemd/system/census-apply.timer
[Unit]
Description=周期性运行 Census reconcile

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl enable --now census-apply.timer
```

（运行同一条 `census apply` 的 `cron` 条目同样可行。）

### 4.2 检查状态与漂移

```sh
census status   --declaration declaration.toml   # 受管账户、版本、漂移；始终以 0 退出
census doctor   --declaration declaration.toml   # 只读的完整性/就绪检查；存在 error 级发现时以非零退出
```

`doctor` 适合接入监控：当某项不变量被违反时，它以非零码退出。

### 4.2.1 审计设备的实际权限

`doctor` 检查 Census *自己的*不变量；**暴露审计**则检查设备的 *ambient* 文件系统权限——
某个主体已能读、能写的内容，无论 Census 配置了什么。它是只读的，同样在出现高严重度发现时
非零退出，因此可以同样的方式接入监控：

```sh
sudo census audit fs                       # 设备态势图（全局可写、setuid、可读密钥……）
sudo census audit expose --principal oper  # oper 账户实际能触及什么，超出它被授予的范围
```

每次创建或收紧受限账户时都运行 `audit expose`，以确认 ambient 文件系统没有给它超出你本意的
东西。完整指南见 [audit.md](audit.md)。

### 4.3 修改角色

编辑 role-store（或声明），预览，然后应用：

```sh
# 编辑 roles/oper.toml —— 增删某个权限
census plan  --declaration declaration.toml --additional-catalog-dir /opt/census/share/permissions   # 预览增量
sudo census apply --declaration declaration.toml --additional-catalog-dir /opt/census/share/permissions --trust-fs --i-understand-no-rescue
```

Census 计算最小更新（增删变化的 sudo 行、组、ACL）——它不会重建账户。

### 4.4 移除角色账户（teardown）

从声明中移除 `[[role_account]]`（或应用空声明以移除**所有**受管账户），然后应用。
Census 删除该账户、其 `sudoers.d` 片段、组成员关系与文件 ACL——fail-closed 且原子：

```sh
census plan --declaration declaration.toml ...        #   DELETE oper (destructive)
sudo census apply --declaration declaration.toml ... --trust-fs --i-understand-no-rescue
```

> teardown 只移除 Census 配置过的东西（记录于 `/var/lib/census/managed.toml`）。外来
> 账户与既有 ACL 绝不被触碰。

---

## 5. managed 模式（简述）

在设备群中，你不会在每台设备上手工编辑声明。而是由控制平面下发**签名的**声明：

- 声明携带 **Ed25519 签名**与**单调版本**；
- `census apply`（不带 `--trust-fs`）在**任何变更前**校验签名并拒绝被回滚的版本；
- 下发、清点、聚合漂移与分阶段 rollout 属于控制平面功能（商业版——见 README 的
  open-core 表）。

§§1–4 的一切均保持不变；你去掉 `--trust-fs`，声明以签名形式到达，而非就地编辑。

---

## 延伸阅读

- [`catalog-authoring.md`](../catalog-authoring.md) —— 编写目录权限与按 OS 的分层（俄文）。
- [`authoring-packages.md`](../authoring-packages.md) —— 编写 add-on 包与精选应用层级（俄文）。
- 仓库的 `README.md` —— 模型、安全属性、CLI 参考与 open-core 边界。
- `examples/` —— 完整可运行的 role-store + 声明。
