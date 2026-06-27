# Design: permission-catalog

Полный продуктовый дизайн с обоснованиями — internal
`specs/2026-06-21-permission-catalog-census-design.md`. Здесь — техническая привязка к коду
Census (public-safe).

## Конвейер компиляции

Раскрытие встроено в резолв role-store, до построения плана:

```text
declaration → role.toml(payload.permissions + сырые) 
           → catalog::resolve(os_target, catalog_dirs)            # § ниже
           → RoleComposition { groups, sudo_cmds, limits } + Provenance
           → model::resolve → ResolvedAccount → plan::diff → apply
```

- `plan`/`apply` работают с ролями в разрешениях напрямую — отдельной обязательной команды
  компиляции на устройстве нет; `census compile` — инспекция.
- В managed-режиме подписывается **скомпилированный срез примитивов** (как сейчас): каталог
  влияет на содержимое до подписи, не на верификацию (trust.rs не меняется).

## Модель каталога

- **Запись политики** (TOML, строгий `deny_unknown_fields`): `id`, `risk` (`contained` |
  `escalation-capable`), `category` (опц.), раскрытие `groups: [String]` / `sudo: [String]`
  (команды) / `limits`, агрегация `includes: [id]` / `include_categories: [String]`. Никаких
  человеко-текстов в записи — они в l10n-дереве.
- **ОС-цель**: `(family, distro, version)` из `/etc/os-release` (`ID`, `VERSION_ID`); маппинг
  семейства зашит (`debian`/`ubuntu`→`linux-…`; `astra`→`astra-…`). Override `--os-target` /
  поле декларации.
- **Цепочка слоёв** снизу вверх: `linux` → `linux-<distro>` → `linux-<distro>-<ver>` →
  `/etc/census/permissions.d/...`. Те же подкаталоги для namespace add-on'ов (`linux/<ns>/` →
  `linux-<distro>/<ns>/` → …). Слияние полей: `<field>.append` добавляет, `replace = true` или
  явное поле — заменяет; provenance запоминает слой-источник. Незнакомая версия → ближайший
  известный слой ниже + lint-warning (не молчаливое «как в последней»).
- **Бандлы**: `includes`/`include_categories` разворачиваются транзитивно (бандл в бандле),
  цикл = ошибка. `include_categories` материализует членство против `catalog_version`,
  резолвнутый список — в provenance. Риск бандла = max(члены); явный `risk` ниже = ошибка.
- **Namespace**: id вне базы обязан нести namespace-префикс (`docker.ps`); коллизия id между
  источниками = ошибка; top-level (без точки) зарезервирован под примитивы ОС.

## Локализация (отдельное дерево)

- `l10n/<locale>/<group>.toml`, секции по id: `[network-admin] title/summary/risk_note`.
  Группировка по файлам — удобство; движок мёржит все файлы локали. Os-агностично (цепочка слоёв
  §ОС не действует); единственное измерение — `/usr/share` overlay'ится `/etc`.
- Fallback отображения: запрошенная локаль → `en` → `id`. Язык: `--lang` → `$LC_MESSAGES` →
  `$LANG` → `en`. Тексты — метаданные: не влияют на раскрытие/риск/резолв/проверки прав.
- Парс l10n: толерантен к незнакомым id (forward/back-compat), строг к структуре. Битый/
  отсутствующий перевод не ломает apply; lint флагует пропуски и осиротевшие ключи.

## Provenance

Скомпилированный срез несёт для каждого примитива: какой `id` его дал → через какой бандл (если
через бандл) → какой слой каталога → `catalog_version`. Реестр managed остаётся **только
примитивы** (lean); provenance восстановим перекомпиляцией против `catalog_version`. `census show`
рендерит дерево; `census compile` — плоский срез + provenance.

## Seam'ы и тестируемость

- `CatalogSource` (trait): чтение/слияние слоёв из набора корней — `LiveCatalog { dirs }` (прод)
  + `FakeCatalog` (in-memory, юнит-тесты резолва/бандлов/циклов без ФС).
- `OsTarget::detect()` из `/etc/os-release`, инъекция пути для тестов; override.
- `catalog::compile(role_permissions, &dyn CatalogSource, os_target) -> Result<(Composition, Provenance), CompileError>`
  — чистое ядро, без ФС/ОС. Ошибки: unknown id, unknown add-on namespace, cycle, namespace
  collision, lowered bundle risk.
- l10n отдельным `L10nSource` (мёрж локали), рендер в CLI.
- Рендер sudoers: `build_sudoers_content` переключается с «ссылка на внешний Cmnd_Alias» на
  конкретные команды раскрытия (argv-безопасно; `visudo -c` валидирует фрагмент как сейчас).
  Параметризованные команды с именем юнита (`service-restart(units)`) ОБЯЗАНЫ эмитить обе формы
  `<unit>` и `<unit>.service` — sudoers матчит аргументы точно (сверено с боевым atm-ansible;
  internal design §7.10). Фрагменты роль-учёток — `NOPASSWD` (вход закрыт, пароля нет).

## Безопасность (дельта)

- Компиляция в root читает файлы каталога и раскрывает в sudo-команды: строгий парс (deny_unknown),
  отказ на незнакомую структуру (урок PwnKit), команды — только из подписанного/ФС-доверенного
  каталога. Угроза-дельта → threat-model §5.14 Census при имплементации.
- Сохранность владения при обновлениях — packaging-инвариант (пакет `census` владеет только
  top-level `<os>/*.toml`, в namespace-подкаталоги не пишет; `/etc` не поставляет). Это свойство
  сборки пакета, не рантайма Census; проверяется в packaging, не юнит-тестом.

## Отклонённые альтернативы

- **Compile в Control/Tessera** (исходный дизайн) — после раскола caталог = домен Census;
  Census-локальный compile делает standalone самодостаточным.
- **Тексты инлайн в записи политики** — мешают community-переводам и смешивают ревью прав с
  ревью текста; вынесены в l10n-дерево.
- **Wildcard-категории без материализации** — тихое расширение прав при росте каталога;
  материализуем членство против `catalog_version`.
- **Раскрытие в mac_mask** — нарушило бы границу с коммерческим ParsecBackend.

## Тестирование

- Unit (FakeCatalog): резолв одного разрешения; цепочка слоёв (append/replace/version override);
  бандл транзитивный; цикл → ошибка; категория-членство + материализация; namespace + коллизия;
  unknown id / unknown add-on; risk=max и занижение; provenance-источники.
- Unit (l10n): мёрж локалей, fallback locale→en→id, overlay /usr←/etc, осиротевший ключ (lint),
  битый файл не ломает.
- Unit (OsTarget): парс os-release (debian/ubuntu/astra), unknown version → ближайший + warning.
- Unit (sudoers): рендер конкретных команд из раскрытия, `visudo`-валидный фрагмент.
- Контейнер: роль в разрешениях → реальные группы/sudoers; add-on docker присутствует/отсутствует;
  `census show --lang ru`; lint-проверки exit-коды.
