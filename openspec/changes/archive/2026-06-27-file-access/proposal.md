# Change: file-access

## Why

Coverage-скан боевой Astra показал `config 0/2657 (0%)`: каталог не умеет явно выдать «читать/
редактировать вот эти файлы/папки». Нужен явный примитив файлового доступа — ro/rw на файлы и
папки. Полный дизайн и обоснование выбора: internal `specs/2026-06-22-file-access-primitive-design.md`.

Ключевые решения: декларативный интент + сменный бэкенд enforcement'а (SPI, как ParsecBackend для
МКЦ); free `AclBackend` держит только ПАПОЧНЫЕ гранты (POSIX ACL + default-ACL — rewrite-proof,
любой инструмент); per-file/pattern/real-time — capability-gated апселл-бэкенды (отказ в free, не
тихое полу-работающее ACL).

## What Changes

- Запись каталога несёт `[[file]]`-гранты: `{ path, access = ro|rw, recursive }`. Путь абсолютный,
  строго валидируется (как sudo); `{param}`-подстановка с пост-валидацией. Форма пути (папка/файл/
  глоб) → требуемая capability.
- **SPI `FileAccessBackend`**: `capabilities()` (dir/per_path/pattern/realtime/rewrite_proof),
  `materialize`/`revoke`/`snapshot`/`restore`. Резолвер маршрутизирует грант на способный бэкенд.
- **Открытый `AclBackend`**: ПАПОЧНЫЕ гранты через `setfacl -R --physical` + default-ACL `-d`
  (наследование новыми файлами → переживает rewrite/ротацию; любой tool). Ставит/снимает ТОЛЬКО
  `u:<role-account>` запись (аддитивно, реестр — авторитет снятия). Откат — `getfacl` снапшот +
  `setfacl --restore`.
- **Capability-gating**: `File`/`Pattern`-грант без установленного способного бэкенда → **отказ**
  до мутаций (fail-closed, с подсказкой «расширь до папки или установи бэкенд»). `compile --lint`
  ловит до apply.
- **Раскрытие**: `PermissionDef.files` → `ResolvedPermission/Account.file_grants` (union по path,
  max-access, recursive=OR), provenance + shape.
- **Managed/отзыв**: `ManagedAccount.file_grants` (персист, serde default); diff → Update/revoke;
  фаза apply после sudoers, snapshot в backup-set.
- **Coverage**: `config`-класс покрыт ⇔ путь под грантом (recursive → поддерево); ro/rw различать;
  отчёт указывает бэкенд+гарантию. Знаменатель config сужается до security-relevant.
- **Риск**: rw на root-эквивалентные пути / ro на секреты = escalation-capable честно; lint/doctor.
- CLI `compile`/`show` рендерят гранты (shape, бэкенд, риск); `doctor` — ACL-дрейф.
- Стартовый каталог: папочные гранты ключевым разрешениям (ssh-admin/pam-config/audit-config/
  log-read/ca-trust-admin/journald-config…) + l10n.

## Impact

- Affected specs: новая capability `file-access` (расширяет permission-catalog + provisioning).
- Affected code (Rust, `census`): catalog.rs (FileGrant/shape/резолв/валидация), новый модуль
  fileaccess.rs (SPI `FileAccessBackend` + `AclBackend` + Fake), model.rs/state.rs/plan.rs
  (file_grants + diff/отзыв), apply.rs (фаза + snapshot в backup-set), coverage.rs (config-класс
  + бэкенд/гарантия), cli.rs/doctor.rs (рендер + дрейф), стартовый каталог + l10n.
- Зависит от `permission-catalog`. Граница МКЦ держится: ACL дискреционно ВНУТРИ мандатного
  потолка PARSEC (коммерческий ParsecBackend), Census метки не ставит. Новый тип мутации (setfacl)
  + будущая SPI-загрузка коммерческих `.so` — угроза-дельта threat-model §5.14.
- fail-closed: невалидный путь/параметр или грант без способного бэкенда → отказ до мутаций.
