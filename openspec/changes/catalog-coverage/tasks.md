# Tasks: catalog-coverage

Реализуется ПОСЛЕ `permission-catalog` (потребляет раскрытие каталога). Каждый срез: TDD,
`cargo test` + `cargo clippy --all-targets -- -D warnings` зелёные, master-code-reviewer.

## Срез 1. Перечисление поверхности
- [ ] 1.1 `SurfaceObject`/`SurfaceClass`/`Provenance`; `SurfaceScanner` trait.
- [ ] 1.2 `LiveSurface`: setuid/setgid (обход реальных ФС `-xdev`, пропуск виртуальных),
      sudo-бинари (`/usr/sbin`,`/sbin`,admin-`/usr/bin`), конфиги (`dpkg-query ${Conffiles}` +
      drop-in + orphan), юниты (`systemctl list-unit-files`), группы (`/etc/group`+`/dev`),
      capfiles (`getcap -r /`); провенанс (`dpkg -S`). Без shell, read-only.
- [ ] 1.3 `FakeSurface` для тестов.

## Срез 2. Ядро расчёта покрытия
- [ ] 2.1 `coverage(surface, catalog, os, roles, ctx) -> CoverageReport` — чистое.
- [ ] 2.2 Правила покрытия: sudo_bin префикс-матч на argv-границе (симлинк→реальный путь);
      config path-glob; unit (`service-admin`|`service-restart(units)` обе формы); group
      set-membership; capfile (`capability-admin`); setuid = inventory/anomalies.
- [ ] 2.3 False-positive: транзитивный побег не плодит покрытие; аргументная гранулярность;
      варианты бинаря по семейству; `--strict` для параметризованных без инстанса.
- [ ] 2.4 intentionally-uncovered с причиной (su/sudo/pkexec; pdpl/МКЦ; app/admin-группы; шум).
- [ ] 2.5 Unit (FakeSurface+FakeCatalog) на каждый класс и каждое правило.

## Срез 3. CLI
- [ ] 3.1 `census catalog coverage` (группа `catalog`) + флаги `--json --os-target --catalog-dir
      --roles --strict --class --min-coverage --include-low-priority --cache`.
- [ ] 3.2 Human-вывод (сводка + непокрытое по доменам + suggested + intentional + anomalies);
      `--json` (массив + сводка). `--min-coverage` → ненулевой код (CI-gate).
- [ ] 3.3 Unit: рендер human/json; exit-код `--min-coverage`.

## Срез 4. Контейнер
- [ ] 4.1 rust:bookworm с известным набором sbin/conffiles/units → детерминированный отчёт +
      exit-код `--min-coverage`; кросс-аудит `--os-target`.

## Проверки
- [ ] 5.1 `cargo test`+`cargo clippy --all-targets -- -D warnings` зелёные.
- [ ] 5.2 master-code-reviewer; фикс CRITICAL/HIGH (read-as-root поверхность — PwnKit-уроки).
- [ ] 5.3 `openspec validate catalog-coverage --strict`.
