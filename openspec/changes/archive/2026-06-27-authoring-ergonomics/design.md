# Design: authoring-ergonomics

## Решения

### 1. Две версии: `schema` (формат) vs `version` (контент)

Раздельные поля, разные роли — не объединять:

| Поле | Семантика | Enforce |
|------|-----------|---------|
| `schema: u32` | версия формата парсера | `schema > SUPPORTED_SCHEMA` → отказ до мутаций; `schema <` — резерв под миграцию |
| `version: u32` | монотонный anti-rollback контента (replay-защита подписи) | `trust.rs`, **только managed/signed**; в `--trust-fs` не проверяется |

`SUPPORTED_SCHEMA` — константа крейта (старт `1`). Парсер проверяет `schema` ПЕРВЫМ, до
остальной валидации: неподдерживаемый формат должен падать с понятным сообщением, а не на
`deny_unknown_fields` где-то внутри. `version` оставляем как есть (поведение не меняется),
только документируем — текущая семантика верная.

Почему раздельно: бамп контента (новая выдача) и смена формата TOML — независимые события.
Слить их в одно поле = либо ложный rollback-отказ при апгрейде формата, либо дыра в
replay-защите при рефакторинге схемы.

### 2. `payload.sudo` — raw escape-hatch, литералы

Парность с каталогом (`sudo = [...]`) и с уже существующим `[[payload.files]]`. Форма —
`Vec<String>` абсолютных путей команд. **Без `{param}`**: параметр-плейсхолдеры держатся
catalog-определением вместе с `[params.X]` constraints (`allow_prefix`, `deny_glob`), инлайн
их подпереть нечем — параметризация с confinement остаётся прерогативой catalog-id.

Материализация: union в `ResolvedAccount.sudo_commands` (тот же путь, что раскрытие каталога) →
sudoers. Валидация значения ПЕРЕД записью: абсолютный путь (`/`-prefix), без shell-метасимволов
(`;|&$<>` и т.п.), не пустой. Невалид → fail-closed на resolve.

Видимость: `show`/`lint` помечают инлайн-sudo как **raw / unlabeled escalation-capable** —
escape hatch обходит risk-label каталога, ревьюер обязан его видеть (как `[[payload.files]]`
сейчас). Доктрина каталога ([[census-curated-package-risk-doctrine]]) не нарушается: примитив
честно помечен «не курирован».

### 3. CLI: additional + no-default

Замена «replace base» на toggle (полезнее — изолированный прогон):

```
(ничего)                                              → дефолты [/usr/share/.., /etc/..]
--additional-catalog-dir P  (repeatable)              → дефолты + P
--no-default-catalog-dirs                             → дефолты выкинуты
--no-default-catalog-dirs --additional-catalog-dir P  → только P
```

`--no-default-catalog-dirs` без `--additional-catalog-dir` → ноль корней → **явный отказ**
(`no catalog roots configured (--no-default-catalog-dirs given without --additional-catalog-dir)`),
exit non-zero. Не молчать, не раскрывать в пустоту.

`--catalog-dir` удаляется жёстко (без hidden-алиаса): репа приватная, внешних юзеров нет,
чище. Один toggle гасит ОБА дефолта; раздельное гашение — отдельные флаги при будущей нужде.

Прецеденс «later wins» (при коллизии permission-id в двух корнях побеждает корень позже по
списку) сохраняется внутри итогового списка корней.

### 4. Контракт

`UPDATE_CONTRACT=1` перегенерит `declaration.schema.json`, `role-store.schema.json`, `cli.json`.
`contract/VERSION` = `census-interface v0` (pre-1.0) — breaking без бампа мажора допустим.
Golden-тесты ([[census-interface-contract]]) ловят неосознанный дрейф; здесь дрейф осознанный.

## Миграция

- Все `examples/*.toml` + тестовые декларации + доки: добавить `schema = 1`.
- Любой вызов `--catalog-dir` в README/доках/CI/скриптах → `--additional-catalog-dir`.
