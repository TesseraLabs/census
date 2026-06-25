# Начало работы с Census

Это руководство проводит оператора через **установку**, **настройку** и
**запуск** Census на одном устройстве, от размещения бинарника до применения
первой декларации и проверки результата, а затем — эксплуатацию во времени.

Census — это *декларативное средство подготовки Unix-объектов доступа*. Нужный
устройству доступ — какие роль-учётки существуют, какие у них группы, правила
`sudo`, лимиты systemd и файловые ACL — описывается в **декларации**, а
`census apply` приводит машину в соответствие. Census идемпотентен (повторный
запуск ничего не меняет, если соответствие уже достигнуто), атомарен (неудачный
apply откатывается) и работает **вне пути аутентификации** — он материализует
OS-объекты, которые аутентификатор проверяет при входе, но сам никого не
аутентифицирует.

Руководство покрывает **standalone**-режим (локально доверенная декларация, без
сервера — путь open-core). Короткий раздел в конце указывает на **managed**-режим
(централизованно подписанная декларация).

> Статус: Census — предрелиз (v0.1.0). Команды и пути ниже актуальны для этой
> версии.

---

## 0. Предварительные требования

Census работает на Linux-устройстве и изменяет локальные базы доступа, поэтому
ему нужны:

- **root** для применения (он вызывает `useradd`/`usermod`/`gpasswd`/`userdel`,
  пишет `sudoers.d`, ставит ACL). Read-only команды (`plan`, `compile`, `show`,
  `status`, `doctor`) root не требуют.
- **shadow-utils** — `useradd`, `usermod`, `gpasswd`, `userdel` (есть в любом
  массовом дистрибутиве).
- **`sudo`** с `visudo` — Census валидирует каждый фрагмент через `visudo -c`
  до активации.
- **`acl`** — `setfacl`/`getfacl`, нужен **только если** роль выдаёт
  файловые permissions (ACL на деревья конфигов/логов). Установить:
  `apt-get install acl` (Debian/Ubuntu/Astra), если отсутствует. Файловые
  grant'ы — **на уровне каталога** (ACL каталога устойчив к перезаписи; grant
  на одиночный файл отклоняется при apply, если не установлен per-file backend).
- **systemd** — для permissions `service-*` (которые авторизуют `systemctl …`)
  и для планирования периодического reconcile (§4.1).

Поддерживаемые семейства дистрибутивов в стартовом каталоге: **Debian 12**,
**Ubuntu 22.04**, **Astra Linux 1.8**. Другой Linux тоже работает; OS-специфика
откатывается к базе семейства.

---

## 1. Установка

Census — один статический бинарник. Нет демона и нет сетевой зависимости в
рантайме.

### 1.1 Получить бинарник

**Вариант A — сборка из исходников** (на build-хосте с Rust stable):

```sh
git clone https://github.com/TesseraLabs/census.git
cd census
cargo build --release
./target/release/census --version
```

**Вариант B — кросс-сборка статического бинарника под устройство**
(рекомендуется для парка устройств, например когда build-хост отличается от
целевого). Сборка `x86_64-unknown-linux-musl` статически слинкована (static-pie)
и не имеет зависимостей от libc/рантайма, поэтому работает на любом glibc/musl
Linux этой архитектуры, включая Astra:

```sh
# на build-хосте (нужен `cross` + Docker либо musl-тулчейн)
cross build --release --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/release/census
#   ... ELF 64-bit LSB pie executable, x86-64, static-pie linked, stripped
```

Скопируйте полученный `census` на устройство.

### 1.2 Разместить и сделать исполняемым

Установите бинарник в каталог из `PATH` root'а (чтобы плановые запуски его
находили):

```sh
sudo install -m 0755 census /usr/local/sbin/census
sudo census --version
```

> **Заметка по Astra Linux.** Под мандатным контролем целостности Astra (МКЦ)
> непривилегированный пользователь не может `chmod +x` свежескопированный файл —
> используйте `sudo install` (как выше) или `sudo chmod +x`. Замкнутая
> программная среда Astra (ЗПС / digsig) **не** мешает бинарнику запускаться,
> когда он исполняемый; Census работает штатно.

### 1.3 Проверить установку

```sh
census --version
census --help          # перечисляет подкоманды: plan, apply, doctor, status,
                       #   compile, show, catalog, framework
command -v setfacl     # нужен только для файловых permissions (§0)
```

---

## 2. Настройка

Рабочая конфигурация — это три вещи: **декларация** (какие учётки подготавливать),
**role-store** (что означает каждая роль) и **каталог** (как permission
разворачивается в OS-примитивы для этого дистрибутива). Стартовый каталог
поставляется вместе с Census, так что на практике достаточно написать
декларацию и role-store.

Каталог `examples/` в репозитории — полный запускаемый образец; скопируйте его
как отправную точку.

### 2.1 Декларация — `/etc/census/declaration.toml`

Декларация перечисляет роль-учётки устройства и привязывает каждую к
стабильному UID:

```toml
version    = 1
role_store = "roles"          # путь к role-store, относительно рабочего
                              #   каталога, из которого запускается census

[defaults]
uid_range = [9000, 9999]      # UID роль-учёток должны попадать в этот диапазон
shell     = "/bin/bash"
home_base = "/var/lib/census/home"

[[role_account]]
role = "oper"                 # должно совпадать со слайсом роли в role-store
uid  = 9001

[[role_account]]
role = "admin"
uid  = 9002
```

- `role_store` разрешается **относительно рабочего каталога**, из которого
  запущен Census. Либо запускайте Census из каталога, содержащего `roles/`,
  либо укажите абсолютный путь.
- Каждый `uid` должен попадать в `[defaults].uid_range`.
- `role` должна именовать слайс, присутствующий в role-store (§2.2).

### 2.2 Role-store — один слайс на роль

Role-store — это каталог слайсов ролей, по одному `<role>.toml` на роль. Слайс
именует **permissions**, которые несёт роль:

```toml
# roles/oper.toml
role    = "oper"
version = 1
os      = "linux"
name    = "Оператор устройства"
level   = 3

[payload]
permissions = [
    "service-restart",                                   # leaf-permission
    "log-read",                                          # ещё один leaf
    { id = "service-control", units = "nginx" },         # параметризованный permission
    "nginx.operate",                                     # курируемый пакет приложения
]
```

Permission — это одно из:

- **leaf** — единичная способность (`log-read`, `network-admin`);
- **bundle** — permission, агрегирующий другие, разрешается транзитивно
  (`network-config` = `network-diag` + `network-admin` + `firewall-admin` + …);
- **параметризованный permission** — `{ id = "service-control", units = "nginx" }`
  привязывает unit(ы), к которым применяется permission;
- **курируемый пакет приложения** — `<app>.{observe|operate|admin}` (например
  `nginx.operate`, `salt-minion.admin`), готовый тир для распространённого
  сервиса. См. §2.4.

Чтобы увидеть существующие permissions, просмотрите дерево каталога (§2.3) или
разверните роль через `census compile` / `census show` (§3.2).

### 2.3 Каталог и таргетинг по ОС

**Каталог** превращает permissions в конкретные OS-примитивы (`groups`,
команды `sudo`, `limits`, файловые ACL). Стартовый каталог поставляется внутри
Census в `share/permissions/`. Укажите дополнительный корень каталога через
`--catalog-dir` (повторяемо; более поздние корни побеждают):

```sh
census compile oper --catalog-dir /opt/census/share/permissions
```

Каталог **слоистый по ОС**: permission разрешается по цепочке
`linux → linux-debian → linux-debian-12` (а также `linux-ubuntu`,
`linux-astra`), так что один и тот же `firewall-admin` разворачивается в `nft`
или `ufw` по обстоятельствам. Census **автоматически определяет** ОС из
`/etc/os-release`; переопределите явно при компиляции на другом хосте:

```sh
census compile oper --os-target linux-astra-1.8
census compile oper --os-target linux-debian-12
```

> Если точного слоя версии нет (например `linux-astra-1.8`), Census разрешает
> против ближайшего базового слоя (`linux-astra`) и предупреждает — это
> ожидаемо, не ошибка.

### 2.4 Курируемые пакеты приложений

Для распространённых сервисов каталог поставляет готовые пакеты permissions по
конвенции `<app>.{observe | operate | admin}`:

- **observe** — только чтение: статус сервиса + read-only ACL на конфиг и логи
  приложения. Всегда `contained`.
- **operate** — жизненный цикл (start/stop/restart) плюс чтение; для сервиса,
  чей демон работает **не от root**, `operate` может нести и rw-конфиг.
- **admin** — read-write конфигурация; `escalation-capable`, когда демон
  работает от root и его конфиг может загрузить код (перезапись конфига — путь
  к root).

Пакеты поставляются для сервисов мониторинга/логирования/edge/kiosk (например
`nginx`, `postgresql`, `redis`, `mosquitto`, `salt-minion`, `rsyslog`, `docker`,
`pcscd`, `chromium`, …). Каждый тир несёт **честный класс риска** (`contained`
против `escalation-capable`) — см. §2.5.

### 2.5 Классы риска

Каждый permission и тир пакета помечен:

- **`contained`** — доступ сам по себе не может поднять непривилегированного
  субъекта до root (только чтение, чистый жизненный цикл или rw-конфиг демона,
  работающего не от root).
- **`escalation-capable`** — доступ даёт путь к root (группа `docker`,
  `sudo ALL` или rw-конфиг root-демона, способного загрузить shared object /
  запустить программу — `load_module` у `nginx`, смена master у `salt-minion`,
  `omprog` у `rsyslog`, …).

Census никогда не выдаёт permission за «ограниченный», когда путь к root
существует. Смотрите класс любой роли через `census show <role>` (§3.2).

### 2.6 Standalone против managed (доверие)

- **Standalone** (это руководство): декларация доверяется по **целостности
  файловой системы** — достаточно передать `--trust-fs` при apply. Без сервера,
  без подписи. Это путь open-core.
- **Managed**: декларация **подписана Ed25519** с монотонной anti-rollback
  версией, проверяется до любой мутации. Доставка подписанной декларации
  выполняется control plane (например, Tessera). См. §5.

---

## 3. Первый запуск

Пройдите `plan` → `compile`/`show` (осмотр) → `apply` (мутация) → проверка.

> Сначала запускайте read-only команды; ничего до `apply` систему не меняет.

### 3.1 Предпросмотр плана

`plan` показывает действия create/update/delete, ничего не трогая:

```sh
cd /etc/census          # чтобы role_store="roles" разрешился
census plan --declaration declaration.toml --catalog-dir /opt/census/share/permissions
#   CREATE oper  (uid 9001, shell /bin/bash)
#   CREATE admin (uid 9002, shell /bin/bash)
```

### 3.2 Осмотреть разворот роли

`compile` разворачивает роль в плоские OS-примитивы с provenance (какой
permission породил каждую строку `sudo` / группу / файловый grant):

```sh
census compile oper --declaration declaration.toml \
  --catalog-dir /opt/census/share/permissions --os-target linux-astra-1.8 --lint
```

`show` рендерит то же как локализованное дерево permissions → примитивы, с
классом риска каждого (используйте `--lang en|ru|zh`):

```sh
census show oper --lang ru --catalog-dir /opt/census/share/permissions
```

Используйте `--lint` у `compile` в CI: он завершается ненулевым кодом при любой
ошибке линта каталога.

### 3.3 Применить

`apply` выполняет **verify → plan → backup → apply**. В standalone-режиме
передайте `--trust-fs`. На устройстве без другого настроенного пути входа
`apply` отказывается продолжать (anti-lockout) без явного подтверждения флагом
`--i-understand-no-rescue`:

```sh
cd /etc/census
sudo census apply \
  --declaration declaration.toml \
  --catalog-dir /opt/census/share/permissions \
  --trust-fs \
  --i-understand-no-rescue
#   census: create: create oper (uid 9001)
#   census: create: create admin (uid 9002)
#   census: file-access: materialized N grant(s) for oper
#   census: all phases succeeded
#   applied: 2 mutation(s)
```

Что делает `apply`, по порядку:

1. **Проверяет** доверие (файловая система в standalone; подпись + anti-rollback
   в managed).
2. **Снимает снапшот** `/etc/passwd`, `/etc/shadow`, `/etc/group`,
   `/etc/gshadow` и затронутых `sudoers.d/census-*`, плюс ACL любых выданных
   путей. Сбой фазы восстанавливает это **атомарно** — Census никогда не
   применяет наполовину.
3. **Создаёт/обновляет/удаляет** учётки через shadow-utils. Каждая роль-учётка
   создаётся с **заблокированным паролем** (`!` в shadow) и **без
   `authorized_keys`** — единственный путь входа — PAM-сервис аутентификатора.
4. **Пишет `sudoers.d/census-<role>`**, валидируя через `visudo -c`. Sudoers
   роль-учёток — `NOPASSWD` (у учётки нет пароля для запроса).
5. **Ставит членство в группах и файловые ACL.**

Census отслеживает только то, что создал сам, в root-only реестре
(`/var/lib/census/managed.toml`), и никогда не трогает чужие учётки и группы.

> **Live-session reconcile.** Деструктивное изменение роль-учётки с живой
> сессией откладывается — Census читает реестр сессий Tessera из
> `--sessions-file` (по умолчанию `/run/tessera/sessions.json`; отсутствие
> файла означает отсутствие живых сессий) и никогда не рвёт идущую сессию.

### 3.4 Проверить результат

```sh
getent passwd oper admin                 # учётки существуют с заявленными UID
sudo cat /etc/sudoers.d/census-oper      # развёрнутые правила sudo
id oper                                  # членство в группах
sudo getfacl -p /etc/nginx               # файловые ACL (если есть файловый grant)
sudo -l -U oper                          # что oper авторизован запускать
```

Можно также подтвердить обратный поиск — какие permissions дали бы доступ к
пути:

```sh
census catalog which-grants /etc/nginx --catalog-dir /opt/census/share/permissions --os-target linux-astra-1.8
```

---

## 4. Эксплуатация

### 4.1 Плановый reconcile

Census задуман для **периодического** запуска, который переутверждает
соответствие и подхватывает изменения декларации. systemd-таймер — простейший
планировщик:

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
  --catalog-dir /opt/census/share/permissions \
  --trust-fs --i-understand-no-rescue
```

```ini
# /etc/systemd/system/census-apply.timer
[Unit]
Description=Периодический reconcile Census

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

(Запись в `cron`, запускающая ту же строку `census apply`, работает так же.)

### 4.2 Проверка состояния и дрейфа

```sh
census status   --declaration declaration.toml   # managed-учётки, версия, дрейф; всегда выходит с 0
census doctor   --declaration declaration.toml   # read-only проверки целостности/готовности; ненулевой код при findings уровня error
```

`doctor` — то, что стоит завести в мониторинг: он завершается ненулевым кодом,
когда нарушен инвариант.

### 4.3 Изменить роль

Отредактируйте role-store (или декларацию), сделайте предпросмотр, затем
примените:

```sh
# отредактируйте roles/oper.toml — добавьте или уберите permission
census plan  --declaration declaration.toml --catalog-dir /opt/census/share/permissions   # предпросмотр дельты
sudo census apply --declaration declaration.toml --catalog-dir /opt/census/share/permissions --trust-fs --i-understand-no-rescue
```

Census вычисляет минимальное обновление (добавить/убрать изменившиеся строки
sudo, группы, ACL) — он не пересоздаёт учётку.

### 4.4 Удалить роль-учётку (teardown)

Уберите `[[role_account]]` из декларации (или примените пустую декларацию,
чтобы удалить **все** managed-учётки), затем примените. Census удаляет учётку,
её фрагмент `sudoers.d`, членство в группах и файловые ACL — fail-closed и
атомарно:

```sh
census plan --declaration declaration.toml ...        #   DELETE oper (destructive)
sudo census apply --declaration declaration.toml ... --trust-fs --i-understand-no-rescue
```

> Teardown удаляет только то, что подготовил Census (отслежено в
> `/var/lib/census/managed.toml`). Чужие учётки и предсуществующие ACL не
> трогаются.

---

## 5. Managed-режим (кратко)

В парке устройств декларацию не редактируют вручную на каждом устройстве.
Вместо этого control plane доставляет **подписанную** декларацию:

- декларация несёт **подпись Ed25519** и **монотонную версию**;
- `census apply` (без `--trust-fs`) проверяет подпись и отвергает откатанную
  версию **до любой мутации**;
- доставка, инвентаризация, агрегированный дрейф и поэтапный rollout — функции
  control plane (коммерческие — см. таблицу open-core в README).

Всё из §§1–4 применяется без изменений; `--trust-fs` опускается, а декларация
приходит подписанной, а не правится на месте.

---

## Дальнейшее чтение

- [`catalog-authoring.md`](../catalog-authoring.md) — авторинг permissions
  каталога и слоёв по ОС.
- [`authoring-packages.md`](../authoring-packages.md) — авторинг add-on пакетов
  и курируемых тиров приложений.
- `README.md` репозитория — модель, свойства безопасности, справочник CLI и
  граница open-core.
- `examples/` — полный запускаемый role-store + декларация.
