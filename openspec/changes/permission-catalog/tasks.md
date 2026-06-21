# Tasks: permission-catalog

Объём большой — срезами. Каждый срез: TDD, `cargo test` + `cargo clippy -- -D warnings` зелёные,
master-code-reviewer, фикс CRITICAL/HIGH.

## Срез 1. Формат каталога + ОС-цель + слоёный резолв (leaf)
- [ ] 1.1 `catalog.rs`: запись политики (id, risk, category, groups, sudo, limits) — строгий
      `deny_unknown_fields`; `risk` enum.
- [ ] 1.2 `OsTarget::detect()` из `/etc/os-release` (инъекция пути); маппинг семейств
      (debian/ubuntu/astra); override-значение.
- [ ] 1.3 `CatalogSource` trait + `LiveCatalog { dirs }` + `FakeCatalog`. Цепочка слоёв
      `linux → linux-<distro> → linux-<distro>-<ver> → /etc`; слияние `field.append` / `replace`.
- [ ] 1.4 Резолв одного разрешения (leaf) в примитивы + provenance слоя. Незнакомая версия →
      ближайший ниже + warning. Unknown id → ошибка.
- [ ] 1.5 Unit: leaf-резолв, append/replace/version-override, unknown id, unknown version.

## Срез 2. Бандлы, категории, namespace add-on
- [ ] 2.1 `includes` транзитивный резолв; детект циклов → ошибка.
- [ ] 2.2 `include_categories`: материализация членства против `catalog_version`; список членов в
      provenance.
- [ ] 2.3 Риск бандла = max(члены); занижение явного `risk` → ошибка.
- [ ] 2.4 Namespace: id-префикс вне базы; коллизия id → ошибка; discovery сканирует `<os>/*.toml`
      и `<os>/*/*.toml`; ссылка на отсутствующий namespace → ошибка резолва.
- [ ] 2.5 Unit: бандл-дерево, цикл, категория+материализация, namespace+коллизия, отсутствующий
      add-on, risk=max/занижение.

## Срез 3. Compile в резолве apply/plan + provenance + sudoers
- [ ] 3.1 `payload.permissions` в role-slice (строки и `{id, params}`); сырые поля = escape hatch.
- [ ] 3.2 `model::resolve` идёт через `catalog::compile` → `RoleComposition` (groups, sudo-команды,
      limits) + provenance; сырые поля union'ятся (lint-warning).
- [ ] 3.3 `sudoers::build_sudoers_content`: рендер **конкретных команд** раскрытия (вместо ссылки
      на внешний Cmnd_Alias); argv-безопасно; `visudo -c`-валидный фрагмент.
- [ ] 3.4 Managed: подпись скомпилированного среза примитивов (trust.rs без изменений — проверить).
- [ ] 3.5 Unit: permissions→ResolvedAccount, union сырых, sudoers-рендер; провенанс в срезе.

## Срез 4. Локализация (отдельное дерево)
- [ ] 4.1 `L10nSource`: `l10n/<locale>/<group>.toml` (ключ=id), мёрж файлов локали, overlay
      `/usr`←`/etc`; толерантный парс id, строгий структуры.
- [ ] 4.2 Fallback `locale → en → id`; источник языка `--lang`/`$LC_MESSAGES`/`$LANG`.
      Поддержать локали стартового набора: `en`, `ru`, `zh`.
- [ ] 4.3 Unit: мёрж, fallback, overlay, осиротевший ключ, битый файл не ломает.

## Срез 5. CLI compile/show + lint
- [ ] 5.1 `census compile <role> [--os-target] [--catalog-dir] [--lint]` — плоский срез +
      provenance; exit-код по lint-ошибкам.
- [ ] 5.2 `census show <role> --lang <l>` — дерево разрешение/бандл → примитив, локализованные
      тексты, классы риска.
- [ ] 5.3 Lint-набор (compile --lint / часть doctor): сырые примитивы помимо разрешений, незнакомая
      ос/версия, override vendor без флага, дельта членства бандла, занижение риска бандла,
      недостающие/осиротевшие переводы, коллизия namespace, id без namespace вне базы.
- [ ] 5.4 Unit: каждое lint-правило срабатывает; exit-коды.

## Срез 6. Стартовый каталог + add-on docker + контейнер
- [ ] 6.1 Файлы стартового vendor-каталога (**~70 разрешений, 14 доменов** — build-лист §7.11
      дизайна + research Part B/D, приоритеты 1–4: pam-config/ca-trust-admin/udev-config/
      capability-admin/apparmor-admin → luks/tpm/initramfs/kernel-cmdline/fstab/swap →
      journald/coredump/metrics/nss/polkit → print/audio/display/ups/vpn/route) под
      `share/permissions/` слои `linux`/`linux-debian`/`linux-ubuntu`/`linux-astra`; бандлы
      (host-hardening/boot-admin/storage-admin/observability/device-operator/peripheral-operator).
      Astra-слой несёт `astra-admin`/`astra-console` (сверено). service-restart эмитит обе формы
      `<unit>`/`<unit>.service`. App-группы (bfs_*) НЕ в базе — пример site-слоя в доке.
- [ ] 6.2 l10n `en` + `ru` + `zh` для стартового набора (и для add-on docker).
- [ ] 6.3 Open add-on `docker` (namespace `docker.*`) + его l10n.
- [ ] 6.4 Контейнер: роль в разрешениях → реальные группы/sudoers (`visudo -c`); docker add-on
      присутствует/отсутствует (ошибка резолва); `census show --lang ru`; lint exit-коды.

## Проверки
- [ ] 7.1 `cargo test` (unit + контейнер) зелёные, `cargo clippy --all-targets -- -D warnings` чисто.
- [ ] 7.2 master-code-reviewer по каждому срезу; фикс CRITICAL/HIGH.
- [ ] 7.3 `openspec validate permission-catalog --strict`.
- [ ] 7.4 Угроза-дельта компиляции в root → threat-model §5.14 (tessera-ws).
