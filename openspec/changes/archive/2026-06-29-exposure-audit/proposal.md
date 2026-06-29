# Change: exposure-audit

## Why

Census выдаёт доступ вперёд (file-access, группы, sudoers), но не умеет ответить на обратный
вопрос: «что роль-учётка РЕАЛЬНО может читать/писать в системе — сверх того, что ей выдала
декларация?». Сделали ограниченного юзера, а в ФС лежит world-writable `/var/spool/cron` или
world-readable секрет — least-privilege замысел подорван ambient-правами, и оператор об этом не
знает. Нужен read-only аудит фактического состояния прав ФС: глобальная posture-карта опасных
классов и точная экспозиция под конкретный принципал.

## What Changes

- Новый read-only слой `exposure-audit` (как `doctor`: MUST NOT мутировать ОС/реестр; чисто →
  exit 0; находки ≥ порога → ненулевой код). Один движок, два режима вывода.
- **Permission-индекс** (подход «скан-один-раз»): один обход охваченных корней собирает на инод
  `{path, owner, group, mode, ACL, object-class}`; индекс переиспользуется на все запросы прогона.
- **`census audit fs`** — глобальная posture-карта principal-independent классов: world-writable в
  чувствительных деревьях, setuid/setgid инвентарь (+флаг writable), world-readable секреты,
  broad-group-writable (`users`/`staff`).
- **`census audit expose --principal <name|uid>`** — экспозиция под учётку: что она достижимо
  читает/пишет. Резолв supplementary-групп (getgrouplist), POSIX access-check **с обязательной
  x-траверсией каждого предка-каталога** (файл 777 за дир-700-owned-root недостижим → не finding).
  DAC-only: SELinux/AppArmor не учитываются, вердикт = верхняя граница (документируется).
- **Killer-фильтр**: для Census-managed роль-учётки вычитается intended baseline (home + гранты
  каталога) → показывается только ЛИШНИЙ доступ сверх замысла. Для произвольного uid baseline нет
  → сырой reachability.
- **Taxonomy находки**: `principal, path, access(rwx), via(other_bits|group|acl_user|acl_group|
  owner), class(cron|systemd-unit|path-binary|sudoers|config|secret|setuid-binary|generic),
  risk(escalation|leak|tamper), severity, remediation_class(ambient|in-model), hint`.
  `remediation_class` честно делит: `ambient` (source — чужой объект → ручной `chmod`/`setfacl`
  хинт, Census не чинит) vs `in-model` (source — объект Census: своя группа раздута / свой
  file-access грант шире → «сузь декларацию»).
- **Охват**: дефолт = security-relevant корни (configurable: /etc /var /opt /usr/local /srv
  cron/spool home-диры); псевдо-ФС (/proc /sys /dev) и сетевые монтирования пропускаются. Флаги
  `--root PATH` (repeatable), `--full`. TTY без scope-флага → интерактивный выбор важное/полный/
  свои корни. `--format text|json`, JSON — стабильный контракт (golden).
- **Границы v1 (YAGNI)**: только read-only (без chmod/setfacl); finding лишь КЛАССИФИЦИРУЕТ путь,
  TOML-патч НЕ генерирует (отдельный change позже); локальные passwd/group (NSS/LDAP — advisory);
  статика ФС без runtime/сессий; снапшот-персист отложен (v1 = индекс в памяти).

## Capabilities

### New Capabilities

- `exposure-audit`: read-only аудит фактических прав ФС — permission-индекс, глобальная
  posture-карта (`audit fs`) и экспозиция под принципал (`audit expose`) с rigorous reachability
  (POSIX access + ACL + x-траверсия предков), taxonomy находок и remediation-классификацией.

### Modified Capabilities

<!-- Нет изменений требований существующих capability: переиспользование (ACL-чтение, классификатор
     security-relevant путей, finding/exit-code-модель) идёт на уровне реализации, не меняет их спеки. -->

## Impact

- Affected specs: новая capability `exposure-audit`. Существующие (`file-access`,
  `catalog-coverage`, `provisioning-doctor`) НЕ меняются по требованиям — берётся только их код.
- Affected code (Rust, `census`): новый модуль `exposure/` (walk+индекс, access-eval с траверсией,
  principal-резолв, taxonomy/severity, классификаторы object-class/secret/broad-group); `cli.rs`
  (подкоманда `audit fs` / `audit expose`, scope-флаги, интерактивный выбор, text/json-рендер);
  переиспользование ACL-чтения из `fileaccess.rs` (AclBackend) и классификатора security-relevant
  путей из `coverage.rs`; finding/severity/exit-code зеркалят `doctor.rs`; TOML-конфиг
  scan-roots/secret-globs/broad-groups (комменты English, human-text → l10n).
- Контракт CLI/JSON залочен schemars/clap golden (interface-contract; `UPDATE_CONTRACT=1` для
  осознанной правки).
- Read-only: MUST NOT мутировать; новых типов мутаций ОС не вводит. Угроза-дельта threat-model:
  слой только ЧИТАЕТ права (в т.ч. секрет-классы) под root — отчёт сам становится чувствительным
  артефактом (раскрывает карту слабых мест); вывод не должен логировать содержимое секретов, только
  пути/режимы.
