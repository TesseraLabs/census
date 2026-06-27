# Census — авторинг каталога разрешений

Руководство автора каталога: как описывать **разрешения** (permissions) — именованные
капабилити, которые Census раскрывает в конкретные ОС-примитивы (sudo-команды, группы,
file-ACL, лимиты) под целевой дистрибутив. Роли парка ссылаются на разрешения по имени;
один источник политик переиспользуется между ролями.

> Термины — канонический глоссарий Tessera (`роль`, `разрешение`, `выдача`, `enforcement`).
> Комментарии в `.toml` каталога — на английском (конвенция). Человекочитаемый текст
> (`title`/`summary`/`risk_note`) живёт ТОЛЬКО в дереве l10n (`l10n/<locale>/`), не в
> структурных файлах. См. также `authoring-packages.md` (role-store, декларация, подпись).

## 1. Зачем каталог

Вместо ручного написания `sudoers` и списков групп в каждой роли — роли несут
**разрешения** (`network-admin`, `log-read`, `service-control`, …), а каталог разворачивает
их в примитивы для дистрибутива устройства. Это даёт переиспользование, per-OS-различия в
одном месте, честные классы риска и cross-reference на compliance-фреймворки.

Роль ссылается на разрешение в `payload.permissions` (см. `authoring-packages.md` §3):

```toml
[payload]
permissions = [
    "log-read",
    { id = "service-control", units = ["nginx", "app"] },   # параметризованная форма
]
```

## 2. Анатомия разрешения

Файл `share/permissions/<os-layer>/<id>.toml`. Лист (leaf) несёт примитивы:

```toml
id       = "service-control"            # ^[a-z][a-z0-9-]*(\.[a-z0-9-]+)*$ ; = ключ разрешения
risk     = "contained"                  # contained | escalation-capable  (см. §6)
category = "os-config"                  # домен для группировки/каталога

# Примитивы (любая комбинация):
sudo = [                                # абсолютные Cmnd; {param} — шаблон (см. §4)
    "/usr/bin/systemctl start {units}",
    "/usr/bin/systemctl start {units}.service",
]
groups = ["adm", "systemd-journal"]     # членство в группах

[[file]]                                # file-access грант (см. §5)
path      = "/var/log"
access    = "ro"
recursive = true

[limits]                                # systemd/rlimit
nofile = 4096
```

Дополнительно:
- `runas = "app"` — sudo-команды этого разрешения исполняются от имени `app`
  (`(app) NOPASSWD: …`), а не root. Без `runas` — дефолт `(ALL)` (root).
- Все пути sudo — **абсолютные**; control-символы и инъекция параметров отвергаются строго.

## 3. Бандлы, категории, per-OS слои

**Бандл** — разрешение, агрегирующее другие через `includes`:

```toml
id       = "service-restart"
category = "os-config"
includes = ["service-observe", "service-control"]   # union примитивов членов
# risk бандла = max(risk членов); явный risk НИЖЕ вычисленного — ошибка (honest labelling)
```

- `include_categories = ["..."]` — включить все разрешения категории (раскрытие фиксируется
  на версии каталога: позже добавленный член не расширяет уже скомпилированную роль).
- Параметры доходят до членов: каталог сперва флэттенит `includes`, потом подставляет
  `{param}` по плоскому списку. Поэтому `{ id = "service-restart", units = [...] }`
  заполняет `{units}` во ВСЕХ членах.

**Per-OS слои.** Один `id`, разное раскрытие по цепочке `linux → linux-debian →
linux-debian-12` (и `linux-ubuntu`, `linux-astra`). Файл в `linux/` — база; одноимённый в
`linux-astra/` — дельта/переопределение (topmost-setter-wins; `replace=true` затирает
накопленное). Так одно разрешение даёт `nft` vs `ufw`, astra-группы и т.д.

## 4. Параметры и guard rails (обязательны для каждого `{placeholder}`)

`{param}` в `sudo`/`groups`/пути файла заполняется значением из роли. Чтобы роль не могла
подставить произвольное (напр. `path="/etc/shadow"`), КАЖДЫЙ placeholder обязан нести
ограничение `[params.<name>]` — иначе разрешение **отвергается при парсинге** (fail-closed).
Значение, нарушающее ограничение, отвергается при резолве (fail-closed), до материализации.

```toml
sudo = ["/usr/bin/systemctl restart {units}"]
[params.units]
kind = "token"            # портируемый идентификатор; charset + опц. max_len

[params.path]
kind = "path"             # подставленный путь обязан лежать под allow_prefix;
allow_prefix = ["/etc/myapp/"]   # + статический гейт (absolute, без `..`, без control)
deny_glob = true          # дефолт true: glob в значении запрещён

[params.action]
kind = "enum"
values = ["start", "stop", "restart"]
```

- `token` — alnum + `- _ . @ : \ /` (имена юнитов/интерфейсов/юзеров); сепараторы sudoers и
  метасимволы отвергаются.
- `path` — `allow_prefix` (список разрешённых корней) + повторная пост-substitution проверка
  пути; `deny_glob` (дефолт true).
- `enum` — только из `values`.
- Список-параметр (`units = ["a","b"]`) проверяется поэлементно; один плохой элемент валит
  раскрытие целиком.

## 5. File-access: уровни доступа (биты)

Грант `[[file]]` материализуется в POSIX ACL (`setfacl`) под root. `access` — **набор бит**:

| Бит | ACL | смысл |
|---|---|---|
| `read` | `r` | читать содержимое / листинг каталога |
| `write` | `w` | запись |
| `execute` | `x` (файл) | исполнять файл |
| `traverse` | `x` (каталог) | входить/искать в каталоге |

Формы записи `access`:
- компактная строка: `"r"`, `"w"`, `"x"`, `"rx"`, `"wx"`, `"rwx"`;
- legacy-алиасы: `"ro"` = `{read, traverse}` (= ACL `r-X`), `"rw"` = `{read, write, traverse}`
  (= `rwX`) — обратная совместимость сохранена байт-в-байт;
- массив бит: `access = ["read", "execute"]` — канонично для всего за пределами `ro`/`rw`.

`read` и `traverse` разнесены: `read` без `traverse` на каталоге (`r--`) = листинг без входа в
подкаталоги; `read+traverse` (`r-X`) = прежнее поведение `ro`.

> `append`-only и прочее, невыразимое POSIX ACL, **не объявляется** (нет бита, парсинг
> отвергает). Появится с capability/MAC-бэкендом.

Union на одном пути = объединение бит (OR), `recursive` = OR; для каталога с `recursive`
ставится default-ACL (новые файлы наследуют — переживает edit-via-rename и ротацию).

## 6. Честные классы риска (доктрина)

`risk` — `contained` или `escalation-capable`. **Никакой иллюзии «ограниченного sudo» там, где
путь к root существует.** Если капабилити содержит escape к root — помечать
`escalation-capable`, даже если «команда узкая».

Примеры `escalation-capable`: `package-install` (dpkg/apt), `modprobe`, `setcap`, `strace`,
группа `docker`, **редактор под root** (из vi/nano тривиальный shell-escape — `allow_prefix`
ограничивает файл, но не escape).

**Пример: одна задача — два уровня риска.** «Дать править конфиг»:

| механизм | как | risk |
|---|---|---|
| `app-config-edit` | `sudo sensible-editor {path}` (редактор под root) | escalation-capable |
| file-grant | `[[file]] path="/etc/myapp/x.conf" access="rw"` (ACL, без sudo) | contained |

Для большинства правок конфига правильный выбор — **file-grant** (contained): аккаунт правит
файл своим инструментом, пути к root нет. `*-edit`-через-редактор оставлять только там, где
реально нужен интерактивный root-редактор — и честно метить `escalation-capable`.

## 7. l10n

Структурный `.toml` не несёт человеко-текста. На каждый `id` — запись в
`l10n/<locale>/<category>.toml` (en/ru/zh) с `title`/`summary`/`risk_note`. EN — авторитетный,
RU/ZH — переводы. `census show … --lang ru` рендерит локализованный текст. Переводчик правит
l10n, не трогая security-определения.

## 8. CLI автора

```bash
census compile <role> --additional-catalog-dir D --os-target T --lint   # раскрыть разрешения → примитивы + provenance
census show    <role> --lang ru --os-target T                # дерево разрешение→примитив, локализовано
census framework lint     --additional-catalog-dir D                    # валидация маппингов на каталог
census framework coverage <fw>                               # какие контроли ещё не покрыты
census framework risk     <fw>                               # какие контроли маппинг подрывает
```

- `compile --lint` — увидеть точные группы/sudo/файлы/лимиты и provenance (из какого слоя/члена)
  ДО применения; параметры и ограничения проверяются здесь fail-closed.

## 9. Инлайн в роли (escape-hatch) vs разрешение

Роль может задать примитив **инлайн**, минуя каталог: `groups`, `sudo_role`, `limits`,
`[[payload.files]]` (file-грант). Это паритет возможностей, но:
- инлайн помечается lint'ом «prefer permissions» рядом с `permissions`;
- инлайн file-путь **не параметризуется** (placeholder в нём запрещён — заполнять нечем);
- разрешение каталога — предпочтительный путь: переиспользование, risk-класс, l10n,
  cross-ref на фреймворки. Инлайн — для разового/специфичного, что не стоит заводить в каталог.

См. `authoring-packages.md` §3 (инлайн-состав роли) и §5 (предпосылки/материализация).
