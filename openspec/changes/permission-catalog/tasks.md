# Tasks: permission-catalog

Объём большой — срезами. Каждый срез: TDD, `cargo test` + `cargo clippy -- -D warnings` зелёные,
master-code-reviewer, фикс CRITICAL/HIGH.

## Срез 1. Формат каталога + ОС-цель + слоёный резолв (leaf)
- [x] 1.1 `catalog.rs`: запись политики (id, risk, category, groups, sudo, limits) — строгий
      `deny_unknown_fields`; `risk` enum.
- [x] 1.2 `OsTarget::detect()` из `/etc/os-release` (инъекция пути); маппинг семейств
      (debian/ubuntu/astra); override-значение.
- [x] 1.3 `CatalogSource` trait + `LiveCatalog { dirs }` + `FakeCatalog`. Цепочка слоёв
      `linux → linux-<distro> → linux-<distro>-<ver> → /etc`; слияние `field.append` / `replace`.
- [x] 1.4 Резолв одного разрешения (leaf) в примитивы + provenance слоя. Незнакомая версия →
      ближайший ниже + warning. Unknown id → ошибка.
- [x] 1.5 Unit: leaf-резолв, append/replace/version-override, unknown id, unknown version.

## Срез 2. Бандлы, категории, namespace add-on
- [x] 2.1 `includes` транзитивный резолв; детект циклов → ошибка.
- [x] 2.2 `include_categories`: материализация членства против `catalog_version`; список членов в
      provenance.
- [x] 2.3 Риск бандла = max(члены); занижение явного `risk` → ошибка.
- [x] 2.4 Namespace: id-префикс вне базы; коллизия id → ошибка; discovery сканирует `<os>/*.toml`
      и `<os>/*/*.toml`; ссылка на отсутствующий namespace → ошибка резолва.
- [x] 2.5 Unit: бандл-дерево, цикл, категория+материализация, namespace+коллизия, отсутствующий
      add-on, risk=max/занижение.

## Срез 3. Compile в резолве apply/plan + provenance + sudoers
- [x] 3.1 `payload.permissions` в role-slice (строки и `{id, params}`); сырые поля = escape hatch.
- [x] 3.2 `model::resolve` идёт через `catalog::compile` → `RoleComposition` (groups, sudo-команды,
      limits) + provenance; сырые поля union'ятся (lint-warning).
- [x] 3.3 `sudoers::build_sudoers_content`: рендер **конкретных команд** раскрытия (вместо ссылки
      на внешний Cmnd_Alias); argv-безопасно; `visudo -c`-валидный фрагмент.
- [x] 3.4 Managed: подпись скомпилированного среза примитивов (trust.rs без изменений — проверить).
- [x] 3.5 Unit: permissions→ResolvedAccount, union сырых, sudoers-рендер; провенанс в срезе.

## Срез 4. Локализация (отдельное дерево)
- [x] 4.1 `L10nSource`: `l10n/<locale>/<group>.toml` (ключ=id), мёрж файлов локали, overlay
      `/usr`←`/etc`; толерантный парс id, строгий структуры.
- [x] 4.2 Fallback `locale → en → id`; источник языка `--lang`/`$LC_MESSAGES`/`$LANG`.
      Поддержать локали стартового набора: `en`, `ru`, `zh`.
- [x] 4.3 Unit: мёрж, fallback, overlay, осиротевший ключ, битый файл не ломает.

## Срез 5. CLI compile/show + lint
- [x] 5.1 `census compile <role> [--os-target] [--catalog-dir] [--lint]` — плоский срез +
      provenance; exit-код по lint-ошибкам.
- [x] 5.2 `census show <role> --lang <l>` — дерево разрешение/бандл → примитив, локализованные
      тексты, классы риска.
- [x] 5.3 Lint-набор (compile --lint / часть doctor): сырые примитивы помимо разрешений, незнакомая
      ос/версия, override vendor без флага, дельта членства бандла, занижение риска бандла,
      недостающие/осиротевшие переводы, коллизия namespace, id без namespace вне базы.
- [x] 5.4 Unit: каждое lint-правило срабатывает; exit-коды.

## Срез 6. Стартовый каталог + add-on docker + контейнер
- [x] 6.1 Файлы стартового vendor-каталога (**~70 разрешений, 14 доменов** — build-лист §7.11
      дизайна + research Part B/D, приоритеты 1–4: pam-config/ca-trust-admin/udev-config/
      capability-admin/apparmor-admin → luks/tpm/initramfs/kernel-cmdline/fstab/swap →
      journald/coredump/metrics/nss/polkit → print/audio/display/ups/vpn/route) под
      `share/permissions/` слои `linux`/`linux-debian`/`linux-ubuntu`/`linux-astra`; бандлы
      (host-hardening/boot-admin/storage-admin/observability/device-operator/peripheral-operator).
      Astra-слой несёт `astra-admin`/`astra-console` (сверено). service-restart эмитит обе формы
      `<unit>`/`<unit>.service`. App-группы (bfs_*) НЕ в базе — пример site-слоя в доке.
- [x] 6.2 l10n `en` + `ru` + `zh` для стартового набора (и для add-on docker).
- [x] 6.3 Open add-on `docker` (namespace `docker.*`) + его l10n.
- [x] 6.4 Контейнер: роль в разрешениях → реальные группы/sudoers (`visudo -c`); docker add-on
      присутствует/отсутствует (ошибка резолва); `census show --lang ru`; lint exit-коды.

## Проверки
- [x] 7.1 `cargo test` зелёные (826 unit/integration, 0 failed); `cargo clippy --all-targets --locked`
      deny-tier чист (двухуровневый `[lints]`: correctness/style/perf→deny, pedantic/nursery→warn —
      `-D warnings` НЕ применять, это ломает two-tier). Контейнер-харнесс (`tests/integration/`) — в CI.
- [x] 7.2 master-code-reviewer (нет CRITICAL); фикс HIGH H1 (`allow_prefix` sibling-escape — гейт на
      границе компонента `path_at_or_under`, parse fail-closed на префикс без `/`) + MEDIUM M1 (байт-кап
      4 MiB на root-чтения, `fsutil::read_capped`); фикс верифицирован повторным ревью. Follow-up
      (accepted): M2 sudo-команда risk-метка review-only, L1 пост-подстановочный гейт имени группы.
- [x] 7.3 `openspec validate permission-catalog --strict`.
- [x] 7.4 Угроза-дельта компиляции в root → threat-model §5.14 (tessera-ws): CN19 (`{param}`/`allow_prefix`
      инъекция), CN20 (каталог как доверенный root-вход: oversize-кап + risk-мислейбл).
