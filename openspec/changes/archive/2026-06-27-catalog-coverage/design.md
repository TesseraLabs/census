# Design: catalog-coverage

Полное исследование (методология, команды перечисления, ground-truth матрица) — internal
`specs/2026-06-21-permission-catalog-coverage-research.md` (Часть A — поверхность, Часть C — CLI).
Здесь — техническая привязка (public-safe).

## Seam'ы

```text
trait SurfaceScanner { fn scan(&self, classes: &[SurfaceClass]) -> Result<Vec<SurfaceObject>, CoverageError>; }
struct LiveSurface { /* реальная ФС/dpkg/systemctl/getcap */ }
struct FakeSurface { objects: Vec<SurfaceObject> }   // тесты — без ФС

struct SurfaceObject { class: SurfaceClass, key: String, provenance: Provenance, detail: String }
enum SurfaceClass { SudoBin, Config, Unit, Group, CapFile, Setuid }
enum Provenance { Vendor, Addon(String /*pkg*/), Orphan }

fn coverage(surface: &[SurfaceObject], catalog: &dyn catalog::CatalogSource,
            os: &OsTarget, roles: &[ResolvedRole], ctx: &CoverageCtx)
    -> Result<CoverageReport, CoverageError>;   // чистое ядро, тестируемо
```

- Переиспользует `catalog::{CatalogSource, OsTarget, resolve}` из `permission-catalog` — покрытие
  считается против РАСКРЫТЫХ примитивов (groups/sudo/config-paths), не сырого каталога.
- `LiveSurface` оборачивает команды Части A без shell: обход реальных ФС (`findmnt --real`,
  `-xdev`, пропуск `/proc /sys /run /dev`), `dpkg-query -W -f='${Conffiles}'`,
  `systemctl list-unit-files --no-legend`, `/etc/group`+`/dev`, `getcap -r /`, провенанс `dpkg -S`.

## Модель покрытия

- `sudo_bin` покрыт ⇔ реальный путь бинаря = префикс-матч какой-то sudo-строки раскрытия на
  argv-границе (`/usr/sbin/ip` покрывает бинарь `ip`; аргументы — сужение). Симлинки → реальный путь.
- `config` ⇔ путь матчит path-glob `config-edit`-примитива или `app-config-edit(path)` инстанса.
- `unit` ⇔ `service-admin` (все) ИЛИ имя ∈ `service-restart(units)` (обе формы `<u>`/`<u>.service`).
- `group` ⇔ ∈ объединению всех `groups`-раскрытий.
- `capfile` ⇔ есть `capability-admin`.
- `setuid` — не объект выдачи; отдельная inventory/anomalies-секция (orphan setuid = расследовать).
- «Каталог» = установленный vendor + add-on'ы + site `/etc` + опц. `--roles <dir>` (параметризованные
  инстансы). Без `--roles` параметризованные считаются «потенциально покрывающими»; `--strict`
  отключает это допущение.

## False-positive

- Транзитивный побег (через выданный shell/`vi`/`find -exec`) НЕ плодит фиктивное покрытие —
  покрыт сам выданный бинарь, риск наследуется (забота `risk`/курирования, не метрики).
- Аргументная гранулярность: поимённое покрытие (`service-restart(units)`) отличается от
  тотального (`service-admin`) — отчёт не показывает ложные 100%.
- Варианты бинаря (`iptables`/`-save`/`-restore`) каноникализуются по семейству, но не покрывают
  друг друга автоматически.

## Вывод

- Human: сводка по классам + overall %, непокрытое по доменам с `suggested_permission`,
  intentionally-uncovered (с причиной), anomalies (orphan setuid/cap).
- `--json`: `[{class,key,covered,provenance,suggested_permission,intentional_exclusion}]` + сводка
  `{by_class, overall_pct, catalog_version, os_target}`.
- `--min-coverage <pct>` → ненулевой код (CI-gate). Intentionally-uncovered (механизмы эскалации
  su/sudo/pkexec, МКЦ/pdpl, app/admin-группы, шумовые группы) в знаменатель метрики не штрафуют.

## Производительность и безопасность

- Сканирование `/` (setuid/getcap) — самое дорогое: `-xdev`, пропуск виртуальных ФС, параллель,
  опц. `--cache` (инвентарь меняется редко). Бюджет < 5 c на типовом устройстве.
- Read-only, root: только stdout; не запускает выданные бинари, не читает содержимое конфигов
  (пути/провенанс/mode; `--show-content` off), DB/cluster не трогает. Строгий парс os-release/каталога.

## Срезы (tasks)
1. enumeration (`SurfaceScanner`+`LiveSurface`+`FakeSurface`); 2. coverage-ядро (чистое); 3. CLI+json+
`--min-coverage`; 4. контейнер-тест (известный образ → известное покрытие).

## Тестирование

- Unit (FakeSurface + FakeCatalog): каждый класс covered/uncovered; префикс-матч sudo на
  argv-границе; path-glob config; unit поимённо vs service-admin; group set-membership;
  intentionally-uncovered причина; anomalies orphan; `--strict` параметризованные.
- Контейнер: rust:bookworm с известным набором sbin/conffiles → детерминированный coverage-отчёт
  и exit-код `--min-coverage`.
