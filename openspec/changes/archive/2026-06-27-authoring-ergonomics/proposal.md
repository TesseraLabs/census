# Change: authoring-ergonomics

## Why

Четыре эргономических уточнения формата деклараций/ролей и CLI, выявленные в обзоре:

1. **Версия формата отсутствует.** Поле `version` декларации — это монотонный
   anti-rollback счётчик контента (enforce только в managed/signed режиме, `trust.rs`),
   НЕ версия схемы парсера. Несовместимое изменение формата сейчас падает грязно
   (`deny_unknown_fields` → `TomlParse`), без внятного «формат N не поддержан» и без точки
   для будущей миграции парсера.
2. **Примитивы роли и каталога не совпадают.** Роль-payload несёт raw escape-hatch
   `[[payload.files]]` (файловый ACL до уровня пути), но НЕ список sudo-команд — только
   `sudo_role` (ссылка на именованную роль). Каталог-пермишен несёт и `[[file]]`, и
   `sudo = [...]`. Нужна парность: raw-команда в роли, когда команды нет в каталоге.
3. **Каталожные корни нельзя сузить.** `--catalog-dir` лишь дописывает к встроенным
   дефолтам (`/usr/share/census/permissions`, `/etc/census/permissions.d`); отключить
   дефолты (изолированный прогон против только своих корней) нельзя.
4. **Документация** деклараций/ролей не показывает override `shell`/`home`/`user`, не
   объясняет `version`, и устареет по флагам/полям выше.

## What Changes

- **Декларация** (`declaration.rs`): новое поле `schema: u32` — версия формата парсера,
  fail-closed при неподдерживаемой (`schema > SUPPORTED_SCHEMA` → отказ до любых мутаций;
  `schema <` — резерв под ветку миграции). Поле `version` документируется как anti-rollback
  (что это, когда бампать, что в `--trust-fs` не проверяется).
- **Роль-payload** (`rolestore.rs`): новый raw escape-hatch `payload.sudo: Vec<String>` —
  **только литеральные** абсолютные пути команд (без `{param}`; параметризация с
  confinement — через catalog-id). Юнионится в `sudo_commands` тем же путём, что раскрытие
  каталога. Значения валидируются (абсолютный путь, без shell-метасимволов) перед записью в
  sudoers. В `show`/`lint` подсвечивается как **raw / unlabeled escalation-capable**
  (наравне с `[[payload.files]]`).
- **CLI** (`cli_def.rs`, `cli/mod.rs`, `main.rs`): `--catalog-dir` → `--additional-catalog-dir`
  (жёсткая замена, без алиаса — репа приватная, юзеров нет); новый булев
  `--no-default-catalog-dirs` выкидывает встроенные дефолты из списка корней. Edge fail-closed:
  `--no-default-catalog-dirs` без `--additional-catalog-dir` → ноль корней → явный отказ,
  exit non-zero. Затрагивает plan/apply/compile/show/catalog coverage/catalog which-grants/
  framework lint.
- **Документация** (`docs/{en,ru,zh}/toml-reference.md`): `schema`/`version`, override
  `shell`/`home`, created-логин = `role` id, adoption через `user`+`adopt`, дефолтный
  per-account home `<home_base>/<role>`, `[[payload.files]]` + `payload.sudo`, новые флаги.
- **Контракт** (golden, `UPDATE_CONTRACT=1`): `declaration.schema.json` (+`schema`),
  `role-store.schema.json` (+`payload.sudo`), `cli.json` (флаги). `contract/VERSION` остаётся
  `census-interface v0` (pre-1.0, breaking допустим).

## Impact

- Affected specs: `declaration-trust` (поле `schema`, документ `version`), новые требования по
  `payload.sudo` и CLI catalog-флагам.
- Breaking: `--catalog-dir` удаляется (нет алиаса); `schema` — обязательное поле декларации
  (миграция примеров/тестов/доков).
- Security-чувствительно: `payload.sudo` материализуется как root в sudoers → master-code-reviewer
  обязателен на срез 2.
