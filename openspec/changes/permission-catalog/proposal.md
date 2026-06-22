# Change: permission-catalog

## Why

Сегодня роль в role-store несёт **сырые** Unix-примитивы: `payload.groups`, `payload.sudo_role`,
`payload.limits`. Причём `sudo_role` рендерится как `<user> ALL=(ALL) <Cmnd_Alias>`, где сам
`Cmnd_Alias` определяет площадка **вручную** вне Census — то есть Census выдаёт сырьё со ссылкой
на внешне-заданный набор команд, и администратор всё равно пишет sudoers руками. Недостаёт
семантического слоя: оператор хочет описать роль в **способностях** («настраивать сеть», «читать
логи»), а продукт сам раскрывает их в конкретные группы/sudo-команды/лимиты для данной ОС.

Это смысловое ядро Census («группа заявляет способность — продукт выдаёт права»). Дизайн
одобрен (tessera-ws `specs/2026-06-21-permission-catalog-census-design.md`, рефреш
`2026-06-07-permission-catalog-design.md` под раскол на Census). Compile — Census-локально:
устройство знает дистрибутив/версию, само резолвит каталог в плоское раскрытие; standalone
самодостаточен.

## What Changes

- Роль описывается через `payload.permissions` (id-строки и `{id, params}`); сырые `groups`/
  `sudo_role`/`limits` остаются как escape hatch с lint-предупреждением.
- **Каталог разрешений**: именованная способность → раскрытие в `groups` + `sudo` (команды) +
  `limits` для ОС-цели. Строгий парсинг (deny_unknown_fields). Раскрытие НЕ включает `mac_mask`
  (МКЦ-потолок — отдельный коммерческий слой).
- **Слоёный резолв по ОС-цели** из `/etc/os-release`: `linux → linux-<distro> → linux-<distro>-<ver>`
  → overlay `/etc`. Точечное (`sudo.append`/поле) или целиком (`replace`) переопределение.
  Незнакомая версия → ближайший известный слой ниже + предупреждение.
- **Бандлы**: разрешение-агрегат через `includes` / `include_categories`; транзитивный резолв,
  детект циклов, риск = максимум членов; членство категории материализуется против
  `catalog_version` (нет тихого расширения прав).
- **Add-on пакеты** стороннего ПО: namespace-подкаталоги (`<os>/<ns>/*.toml`), id с префиксом
  (`docker.ps`); коллизия id = ошибка; ссылка на отсутствующий add-on = ошибка резолва до apply.
- **Локализация отдельным деревом** `l10n/<locale>/<group>.toml` (ключ = id, os-агностично,
  overlay `/usr`←`/etc`, fallback `locale → en → id`); тексты — метаданные, на раскрытие/проверки
  не влияют; сообщество дополняет переводы, не трогая security-определения.
- **Compile встроен в резолв** role-store: `plan`/`apply` работают напрямую с ролями в
  разрешениях; раскрытие — до diff/плана. Provenance (`catalog_version` + слой/бандл-источник
  каждого примитива). В managed-режиме подписывается уже скомпилированный срез примитивов
  (верификация не меняется).
- **CLI**: `census compile <role>` (плоское раскрытие + provenance) и `census show <role> --lang`
  (дерево разрешение/бандл → примитив, локализованные тексты, классы риска). Классы риска
  (`contained` | `escalation-capable`) — advisory (показ/lint, не enforcement).
- **Lint** (`census compile --lint` / часть `doctor`): сырые примитивы помимо разрешений,
  незнакомая ос-цель/версия, override vendor без флага, дельта членства бандла, занижение риска
  бандла, недостающие/осиротевшие переводы, коллизия namespace, id без namespace от не-базы.
- **Стартовый vendor-каталог** (~35 разрешений в 9 доменах) + open add-on `docker`.

## Impact

- Affected specs: новая capability `permission-catalog`.
- Affected code (Rust, `census`): новый модуль резолва каталога (`catalog.rs`: парс, слоёный
  резолв, бандлы, namespace, provenance, l10n), расширение `rolestore`/`model` (permissions →
  RoleComposition через compile), `sudoers` (рендер конкретных команд вместо ссылки на внешний
  Cmnd_Alias), `cli`/`main` (`census compile`, `show --lang`, `--catalog-dir`/`--os-target`),
  `doctor` (lint-проверки), файлы стартового каталога + l10n + add-on docker под `share/`.
- Объём большой — реализация срезами (см. tasks.md): формат+резолв → бандлы/namespace →
  compile-в-apply+provenance → l10n → CLI/lint → стартовый каталог+docker.
- Без изменений: trust/anti-rollback (подписывается скомпилированный срез как и раньше),
  live-reconcile, backup/shadow-utils, формат декларации (меняется только role-store слой).
- Граница с МКЦ держится: каталог раскрывает только учётко-слой (groups/sudo/limits).
