# Tasks: authoring-ergonomics

TDD по срезам. На каждый срез: `cargo test` + `cargo clippy --all-targets -- -D warnings`
зелёные, master-code-reviewer (срез 2 обязателен — root sudoers). Контракт перегенерится
`UPDATE_CONTRACT=1` в конце затронутого среза. Коммит/PR — вне рабочего окна (08:00–19:00 МСК).

## Срез 1. Декларация: `schema` + документ `version`
- [x] 1.1 `Declaration` += `schema: u32`; константа `SUPPORTED_SCHEMA = 1`.
- [x] 1.2 `validate()`/`parse()`: проверять `schema` ПЕРВЫМ; `schema > SUPPORTED_SCHEMA` →
      новая ошибка `SchemaUnsupported { got, supported }` (fail-closed до прочей валидации).
- [x] 1.3 Документировать `version` (doc-комментарий): anti-rollback, managed-only, когда бампать.
- [x] 1.4 Unit: `schema` отсутствует → ошибка парса; `schema = 1` ок; `schema = 2` →
      `SchemaUnsupported`; порядок (schema-отказ раньше прочих).
- [x] 1.5 Миграция: `examples/declaration.toml` + тестовый `SAMPLE` + доки-сниппеты += `schema = 1`.
- [x] 1.6 Контракт `declaration.schema.json` (`UPDATE_CONTRACT=1`), golden зелёный.

## Срез 2. Роль: `payload.sudo` (raw escape-hatch) — SECURITY
- [x] 2.1 `SlicePayload`/`RoleComposition` += `sudo: Vec<String>` (`#[serde(default)]`).
- [x] 2.2 Валидация значения: абсолютный путь, без shell-метасимволов, не пустой → fail-closed
      на resolve при невалиде.
- [x] 2.3 Резолв: union `payload.sudo` в `ResolvedAccount.sudo_commands` (рядом с раскрытием
      каталога); материализация в sudoers — существующим путём.
- [x] 2.4 `show`/`lint`: пометка инлайн-sudo как raw/unlabeled escalation-capable.
- [x] 2.5 Unit: парс, union с catalog-sudo, отказ на не-абсолютном/метасимвольном пути,
      show/lint-пометка.
- [x] 2.6 Контракт `role-store.schema.json` (`UPDATE_CONTRACT=1`), golden зелёный.
- [x] 2.7 master-code-reviewer (root sudoers материализация).

## Срез 3. CLI: catalog-dir флаги
- [x] 3.1 `--catalog-dir` → `--additional-catalog-dir` во ВСЕХ подкомандах
      (plan/apply/compile/show/catalog coverage/catalog which-grants/framework lint).
- [x] 3.2 Новый булев `--no-default-catalog-dirs` в тех же подкомандах.
- [x] 3.3 `catalog_roots_with_overrides`: при `no_default` не подмешивать `default_catalog_roots`;
      при пустом итоге → ошибка `no catalog roots configured (...)`, exit non-zero.
- [x] 3.4 Unit/CLI-тест: дефолты; +additional; no-default+additional; no-default один → отказ.
- [x] 3.5 Контракт `cli.json` (`UPDATE_CONTRACT=1`), golden зелёный.

## Срез 4. Документация
- [x] 4.1 `docs/{en,ru,zh}/toml-reference.md`: `schema`/`version`; override `shell`/`home`;
      created-логин = role id; adoption `user`+`adopt`; per-account home `<home_base>/<role>`;
      `[[payload.files]]` + `payload.sudo`; новые флаги.
- [x] 4.2 `README.md` + `examples/declaration.toml` шапка-комментарий: `--catalog-dir` →
      `--additional-catalog-dir`, упомянуть `--no-default-catalog-dirs`.
- [x] 4.3 Сверка: ни одного `--catalog-dir` не осталось в репо (grep чисто).
