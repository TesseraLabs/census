# Census — формирование пакетов: маппинг сущностей ОС на роли

Руководство интегратора/оператора: как собрать **Census-пакет** — декларацию и role-store,
которые отображают роли парка на Unix-объекты доступа устройства (учётки, группы, sudo,
лимиты), подписать его и применить.

> Термины — канонический глоссарий Tessera (`роль`, `роль-учётка`, `выдача`, `enforcement`).
> Census приводит ОС в соответствие декларации; он **не** аутентифицирует — вход выполняет
> Tessera по сертификату. Census работает от root, **вне auth-пути**.

## 1. Что такое Census-пакет

Пакет — это три части на устройстве:

| Файл | Назначение | Чувствительность |
|---|---|---|
| **role-store** `<dir>/<role>.toml` | *состав* роли: какие ОС-примитивы несёт роль (группы, sudo, лимиты) | не секретно |
| **declaration.toml** | *учётко-слой*: какие роль-учётки создать (uid/shell/home), ссылка на role-store, `version`, подпись | не секретно |
| **trust.pub** `/etc/census/trust.pub` | публичный ключ, которым подписана декларация (managed-режим) | публичный ключ |

Один источник истины на состав роли — **role-store** (тот же формат, что читает Tessera).
Декларация его **не дублирует**, а ссылается: добавляет только проекцию роли в аккаунт.

## 2. Модель: роль = маппинг сущности на ОС

```
                role.toml (состав)                 declaration.toml (учётко-слой)
  роль "oper" ── groups = ["atm-operators"]   ──┐
                 sudo_role = "atm-ops"           ├─▶  роль-учётка oper
                 limits.nofile = 4096            │     uid=9010 shell=/bin/bash
                                                 │     home=/var/lib/census/home/oper
                                                 │     (пароль заблокирован, без ключей)
```

Census для каждой `[[role_account]]` декларации читает `<role_store>/<role>.toml`, берёт
`payload.groups` / `sudo_role` / `limits` как состав и материализует Unix-аккаунт с этим
составом. Вход в `oper` — только cert-аутентификацией Tessera (§9 ниже).

## 3. role-store: `<role>.toml` (состав роли)

Формат — срез роли Tessera (`os = "linux"`). Census читает **подмножество** для Linux
(`groups`, `sudo_role`, `limits`), прочие поля (`mac_mask` Astra, `selinux`, `session`)
игнорирует толерантно (их валидирует Tessera). Имя файла = `<role>.toml`, `role` внутри =
имя файла.

```toml
# /var/lib/tessera/roles/oper.toml
role = "oper"            # ^[a-z][a-z0-9-]{0,15}$ ; = имя файла = имя роль-учётки
version = 3              # версия среза роли (Tessera-сторона)
os = "linux"
name = "Оператор банкомата"
level = 5                # для UI-выбора у Tessera; Census не использует

[payload]
groups = ["atm-operators", "log-readers"]   # доп-группы роль-учётки
sudo_role = "atm-ops"                        # имя sudo-правила (см. §5)

[payload.limits]
nofile = 4096           # RLIMIT_NOFILE
nproc  = 512            # RLIMIT_NPROC
```

- `role` — ключ; матчит `[[role_account]].role` в декларации.
- `groups` — **доп-группы** роль-учётки. Отсутствующие Census создаёт сам (`groupadd`) и
  управляет ими; пред-существующие/чужие — только назначает членство, не трогает. Для
  стабильного GID по парку — пин в декларации (`[[group]]`, §4).
- `sudo_role` — логическое имя sudo-права; Census кладёт `sudoers.d/census-<role>` (см. §5).
- `limits` — необязательно.

## 4. declaration.toml (учётко-слой)

```toml
# /etc/census/declaration.toml
version = 12                            # монотонный; anti-rollback (§9)
role_store = "/var/lib/tessera/roles"   # откуда брать состав

[defaults]
uid_range = [9000, 9999]               # полоса UID роль-учёток; ≤ UID_MAX ОС (на Astra 60000)
shell = "/bin/bash"                    # дефолтный shell
home_base = "/var/lib/census/home"     # база для home

# опц.: пин GID групп для стабильности по парку (audit/NFS). Census создаст с этим GID.
[[group]]
name = "atm-operators"
gid  = 8010

[[role_account]]
role = "oper"                          # ← состав из role_store/oper.toml
uid  = 9010                            # явный, СТАБИЛЬНЫЙ по парку (§6)
# shell/home — опц., иначе из defaults

[[role_account]]
role = "serv"
uid  = 9020

[[role_account]]
role = "admin"
uid  = 9030
```

- `version` — поднимать при каждом изменении пакета; Census отвергает декларацию с
  `version` меньше последней применённой (anti-rollback).
- `uid` — **обязателен и стабилен** по всему парку (§6).
- Состав (группы/sudo/лимиты) здесь **не указывается** — только в role-store.

## 5. Предпосылки на устройстве

Перед `apply` на устройстве должны существовать:

1. **Группы** из `payload.groups`: Census создаёт отсутствующие сам и управляет ими (с пином
   GID из `[[group]]` или OS-assigned). Пред-создавать заранее нужно лишь если группа уже
   существует у других потребителей (тогда Census её не трогает — только членство).
2. **sudoers-правило для `sudo_role`.** По соглашению role-store sudo выдаётся через группу
   с заранее настроенным правилом, ИЛИ Census кладёт `sudoers.d/census-<role>` с правилом,
   которое валидируется `visudo -c`. Конкретный шаблон правила фиксируется при интеграции
   (Census владеет только файлами `census-*`).
3. **Rescue-канал вне Census** (emergency-аккаунт и/или `sshd UsePAM=no`) — Census его
   структурно не трогает (он не в реестре managed) и не даёт снести (§7/anti-lockout).
4. **trust-anchor** (managed-режим, §9): `/etc/census/trust.pub`.

## 6. Стабильные UID/GID по парку

UID роль-учёток **должны быть одинаковы на всех устройствах** парка (для audit-корреляции и
возможного NFS). Поэтому `uid` задаётся **явно** в декларации, а не выдаётся ОС из счётчика.
Выбирать полосу `uid_range` выше людских UID (≥1000) и ниже `UID_MAX` ОС (на Astra 1.8.4 =
60000). Конфликт UID (занят чужим) → `apply` отказывает, не перезаписывает.

## 7. Применение и проверка

```bash
census plan   --declaration declaration.toml   # сухой прогон: что создать/обновить/удалить
census apply  --declaration declaration.toml --trust-fs   # применить (standalone, §9)
census doctor                                   # проверить инвариант (см. §10)
census status                                   # что под управлением, версия, drift
```

- `apply` **идемпотентен**: повторный прогон той же декларации — no-op.
- `apply` **атомарен**: снимает full-file backup auth-баз перед мутацией; при сбое фазы —
  откат к прежнему состоянию.
- Мутация — через `useradd`/`usermod`/`gpasswd`/`userdel` + `sudoers.d` (через `visudo -c`).
- Реестр managed (`/var/lib/census/managed.toml`) обновляется последним. **Не редактировать
  руками** — это авторитет принадлежности; ручная правка ломает целостность (doctor поймает).

## 8. Жизненный цикл изменений

- **Добавить роль**: создать `<role>.toml`, добавить `[[role_account]]`, поднять `version`,
  (managed) переподписать, доставить, `apply`.
- **Изменить состав** (группы/sudo/лимиты): править `<role>.toml`, поднять `version`, `apply`.
  Census применит дрейф (в т.ч. отзыв sudo — `census-<role>` будет удалён).
- **Убрать роль**: удалить `[[role_account]]` (и опц. `<role>.toml`), поднять `version`,
  `apply` — учётка удаляется (`userdel -r`) с учётом anti-lockout.

## 9. Доверие к пакету: managed vs standalone

### Standalone (`--trust-fs`)
Доверие = целостность ФС/образа (root-only `/etc/census/`). Явный флаг `--trust-fs`,
логируется. Подходит для образов/enrollment без Control. Подпись и anti-rollback не
проверяются.

### Managed (подпись Ed25519)
Декларация подписана ключом Control; `census apply` (без `--trust-fs`) верифицирует подпись
по `/etc/census/trust.pub` **до** любых мутаций (fail-closed), затем anti-rollback по `version`.

**Сборка подписанного пакета** (схема совместима с Tessera-manifest; пример на openssl —
подпись openssl верифицируется реализацией census на ed25519-dalek):

```bash
# 1. ключевая пара парка (одноразово, приватный ключ — у Control, не на устройстве)
openssl genpkey -algorithm ed25519 -out control-signing.key

# 2. trust-anchor на устройство: hex 32-байтного raw Ed25519 public key
openssl pkey -in control-signing.key -pubout -outform DER \
  | tail -c 32 | od -An -tx1 | tr -d ' \n' > trust.pub
#   → разложить как /etc/census/trust.pub (root, 0644) при enrollment

# 3. подписать декларацию: подпись покрывает БАЙТЫ декларации БЕЗ строки `signature`.
#    Берём декларацию без подписи (declaration.toml), подписываем её как есть:
openssl pkeyutl -sign -inkey control-signing.key -rawin -in declaration.toml -out d.sig
SIG=$(od -An -tx1 d.sig | tr -d ' \n')

# 4. prepend строки signature (ТОП-уровень, до первого [table]) — census снимет её и
#    проверит подпись над оставшимися байтами (= исходная declaration.toml):
{ printf 'signature = "%s"\n' "$SIG"; cat declaration.toml; } > declaration.signed.toml

# 5. доставить declaration.signed.toml на устройство, применить БЕЗ --trust-fs:
census apply --declaration declaration.signed.toml
```

Канонизация (важно для совместимости подписи): подписанный payload = байты файла с **полностью
удалённой первой строкой `signature`** (первый непробельный токен `signature`, затем `=`),
включая её перевод строки; UTF-8; размер ≤ 256 KiB.

**Anti-rollback**: последний успешно применённый `version` персистится в
`/var/lib/census/declaration.version`. Декларация с `version` меньше — отвергается; равная —
допустима (no-op); большая — принимается. Всегда **поднимайте `version`** при изменении пакета.

> ГОСТ-подпись — будущее расширение. Сейчас — Ed25519.

## 10. Что Census гарантирует (и что — нет)

**Гарантирует** (проверяется `census doctor`):
- роль-учётка недостижима помимо Tessera: пароль заблокирован (`!`), нет `authorized_keys`;
- managed-объекты соответствуют реестру; чужая учётка с поддельной GECOS-меткой — флаг;
- остался путь входа (anti-lockout, Warn).

**НЕ зона Census**:
- MAC-конверт (Astra МКЦ / `mac_mask`) — назначает коммерческий Tessera ParsecBackend отдельно;
- PAM-стек и сам cert-вход — Tessera Login;
- полный анализ PAM-графа «ни один сервис не пускает помимо tessera» — `doctor` проверяет
  конкретные учётные условия (advisory-ограничение).

## 11. Полный пример: банкомат (oper / serv / admin)

`roles/oper.toml`, `roles/serv.toml`, `roles/admin.toml`:
```toml
# oper.toml — операционная смена
role = "oper"
version = 1
os = "linux"
name = "Оператор"
level = 3
[payload]
groups = ["atm-operators"]
[payload.limits]
nproc = 256
```
```toml
# serv.toml — сервис-инженер
role = "serv"
version = 1
os = "linux"
name = "Сервис-инженер"
level = 5
[payload]
groups = ["atm-operators", "atm-service"]
sudo_role = "atm-service"     # ограниченный sudo на сервисные операции
```
```toml
# admin.toml — администратор устройства
role = "admin"
version = 1
os = "linux"
name = "Администратор"
level = 7
[payload]
groups = ["atm-operators", "atm-service", "atm-admin"]
sudo_role = "atm-admin"
```
`declaration.toml`:
```toml
version = 1
role_store = "/var/lib/tessera/roles"
[defaults]
uid_range = [9000, 9999]
shell = "/bin/bash"
home_base = "/var/lib/census/home"
[[role_account]]
role = "oper"
uid = 9010
[[role_account]]
role = "serv"
uid = 9020
[[role_account]]
role = "admin"
uid = 9030
```
На устройстве (enrollment): разложить trust.pub (для managed). Группы `atm-operators`/
`atm-service`/`atm-admin` Census создаст сам (опц. пин GID через `[[group]]`). Затем
`census plan` → `census apply` (managed: подписать по §9) → `census doctor`.
Результат: три роль-учётки с заблокированными паролями; вход в каждую — только по сертификату
Tessera с допуском к этой роли; различие прав — через группы и sudo, у admin шире.

## 12. Известные ограничения (текущая версия)

- **Живые сессии**: удаление/смена роль-учётки с активной сессией — координация с Tessera
  session-registry ещё не реализована; применять в окно обслуживания.
- **Astra/ЗПС**: бинарь `census` под замкнутой программной средой требует подписи (bsign) —
  вопрос упаковки/деплоя, не формата пакета.
- **sudoers-шаблон** для `sudo_role` фиксируется при интеграции (соглашение role-store).
