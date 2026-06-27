# Tasks: catalog-coverage

Реализуется ПОСЛЕ `permission-catalog` (потребляет раскрытие каталога). Каждый срез: TDD,
`cargo test` + `cargo clippy --all-targets -- -D warnings` зелёные, master-code-reviewer.

## Срез 1. Перечисление поверхности
- [x] 1.1 `SurfaceObject`/`SurfaceClass`/`Provenance`; `SurfaceScanner` trait.
- [x] 1.2 `LiveSurface`: setuid/setgid (обход реальных ФС `-xdev`, пропуск виртуальных),
      sudo-бинари (`/usr/sbin`,`/sbin`,admin-`/usr/bin`), конфиги (`dpkg-query ${Conffiles}` +
      drop-in + orphan), юниты (`systemctl list-unit-files`), группы (`/etc/group`+`/dev`),
      capfiles (`getcap -r /`); провенанс (`dpkg -S`). Без shell, read-only.
- [x] 1.3 `FakeSurface` для тестов.

## Срез 2. Ядро расчёта покрытия
- [x] 2.1 `coverage(surface, catalog, os, roles, ctx) -> CoverageReport` — чистое.
- [x] 2.2 Правила покрытия: sudo_bin префикс-матч на argv-границе (симлинк→реальный путь);
      config path-glob; unit (`service-admin`|`service-restart(units)` обе формы); group
      set-membership; capfile (`capability-admin`); setuid = inventory/anomalies.
- [x] 2.3 False-positive: транзитивный побег не плодит покрытие; аргументная гранулярность;
      варианты бинаря по семейству; `--strict` для параметризованных без инстанса.
- [x] 2.4 intentionally-uncovered с причиной (su/sudo/pkexec; pdpl/МКЦ; app/admin-группы; шум).
- [x] 2.5 Unit (FakeSurface+FakeCatalog) на каждый класс и каждое правило.

## Срез 3. CLI
- [x] 3.1 `census catalog coverage` (группа `catalog`) + флаги `--json --os-target --catalog-dir
      --roles --strict --class --min-coverage --include-low-priority --cache`.
- [x] 3.2 Human-вывод (сводка + непокрытое по доменам + suggested + intentional + anomalies);
      `--json` (массив + сводка). `--min-coverage` → ненулевой код (CI-gate).
- [x] 3.3 Unit: рендер human/json; exit-код `--min-coverage`.

## Срез 4. Контейнер
- [x] 4.1 rust:bookworm с известным набором sbin/conffiles/units → детерминированный отчёт +
      exit-код `--min-coverage`. ПРОГНАНО 2026-06-27 в docker (rust:bookworm, живая поверхность)
      через `tests/integration/container-apply.sh` sc.25–27 (122/0): read-only summary; `--min-coverage 100`
      → exit 4 (не error 1); `--json` (`overall_pct`+`by_class`); unknown class → non-zero; `--min-coverage 0`
      → exit 0. Нюанс: кросс-аудит `--os-target` — флаг есть + unit-тесты, в контейнере отдельно не ассертился.

## Проверки
- [x] 5.1 `cargo test` зелёные (837, 0 failed); `cargo clippy --all-targets --locked` deny-tier чист
      (two-tier `[lints]`; `-D warnings` НЕ применять — ломает two-tier).
- [x] 5.2 master-code-reviewer (нет CRITICAL); фикс HIGH-1 (тихая деградация скан-тула маскировала
      `--min-coverage` gate → `CaptureOutcome` absent/degraded, fail-closed exit 4, scan_warnings) +
      MEDIUM (File/Pattern не enforce-able → не `covered`; admin-флаг только на resolve Ok; timeout 60s
      на внешние команды, `getcap` без кросс-mount). Фикс верифицирован повторным ревью. Follow-up
      (accepted): MEDIUM-4 (parse_getcap whitespace), LOW (try_wait Err-арм reap, intentional-exclusion prefix).
- [x] 5.3 `openspec validate catalog-coverage --strict`.
