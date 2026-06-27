# Change: catalog-coverage

## Why

Каталог разрешений (`permission-catalog`) раскрывает способности в Unix-примитивы. Но как
куратору каталога и standalone-оператору **убедиться, что ничего не забыто** — что все
стандартные привилегированные объекты системы (setuid-бинари, админ-утилиты `/usr/sbin`,
security-конфиги `/etc`, systemd-юниты, привратные группы) покрыты хотя бы одним разрешением?
Сейчас способа нет. `census catalog coverage` перечисляет живую привилегированную поверхность
устройства и показывает, что НЕ покрыто установленным каталогом — гарантия полноты и сигнал
курирования (исследование: internal `specs/2026-06-21-permission-catalog-coverage-research.md`).

## What Changes

- Новая read-only подкоманда `census catalog coverage` (root): перечисляет привилегированную
  поверхность и считает покрытие против установленного каталога (+ add-on'ы + site-слой + опц.
  роли), репортит непокрытое и сводку %.
- **Классы поверхности**: `sudo_bin` (`/usr/sbin`,`/sbin`,admin-`/usr/bin`), `config`
  (security-relevant `/etc`, drop-in, conffiles), `unit` (systemd), `group` (привратные к `/dev`),
  `capfile` (`getcap`), `setuid` (инвентарь/аномалии). Перечисление — теми же источниками, что в
  исследовании (Part A): обход реальных ФС `-xdev`, `dpkg-query ${Conffiles}`,
  `systemctl list-unit-files`, `/etc/group`+`/dev`, `getcap -r /`, провенанс `dpkg -S`.
- **Модель покрытия**: `sudo_bin` покрыт ⇔ путь — префикс-матч sudo-строки раскрытия (на
  argv-границе); `config` ⇔ path-glob `config-edit`-примитива; `unit` ⇔ `service-admin` или имя ∈
  `service-restart(units)` (обе формы `<unit>`/`<unit>.service`); `group` ⇔ ∈ объединению
  `groups`-раскрытий; `capfile` ⇔ есть `capability-admin`. setuid — отдельная inventory/anomalies
  секция (не объект выдачи).
- **OS-target** из `/etc/os-release` (как apply) → сравнение с тем же слоем каталога; `--os-target`
  для кросс-аудита.
- **Вывод**: human (сводка + непокрытое по доменам + suggested permission + intentionally-uncovered
  + anomalies) и `--json` (машиночитаемо для CI). `--min-coverage <pct>` → ненулевой код
  (CI-gate / lint-сигнал «покрытие упало после обновления пакетной базы»).
- **False-positive**: транзитивные побеги не плодят фиктивное покрытие (риск — забота `risk`-
  маркировки); аргументная гранулярность различается (поимённо vs `service-admin`); варианты
  бинаря (`iptables`/`-restore`) каноникализуются по семейству, но не покрывают друг друга
  автоматически; симлинки резолвятся до реального пути.
- **Intentionally-uncovered** помечается причиной: механизмы эскалации (`su`/`sudo`/`pkexec`),
  МКЦ/`pdpl` (commercial), app/admin-группы (`astra-admin`/`app_*` — site-слой), шумовые группы.

## Impact

- Affected specs: новая capability `catalog-coverage` (потребитель `permission-catalog`).
- Affected code (Rust, `census`): новый модуль `coverage.rs` (`SurfaceScanner` trait +
  `LiveSurface` + `FakeSurface`; чистое ядро `coverage(surface, catalog, roles) -> CoverageReport`),
  `cli`/`main` (`census catalog coverage` + флаги + json), переиспользует `catalog::CatalogSource`/
  `OsTarget` из `permission-catalog`.
- **Зависит от `permission-catalog`** (раскрытие каталога = вход расчёта покрытия) — реализуется
  ПОСЛЕ него.
- Read-only, root: ничего не пишет (кроме stdout), не запускает выданные бинари, не читает
  содержимое конфигов (только пути/провенанс/mode; `--show-content` off по умолчанию). DB/cluster
  не трогает. Строгий парс os-release/каталога.
- Граница: МКЦ/pdpl и app-группы — `intentionally-uncovered`, не пробел.
