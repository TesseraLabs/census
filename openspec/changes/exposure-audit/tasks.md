# Tasks: exposure-audit

Read-only слой. Реализация на Rust через сабагента `rust-pro`, срезами, TDD. На каждый срез:
`cargo test` + `cargo clippy --all-targets -- -D warnings` зелёные, ревью `master-code-reviewer`.
Слой строго read-only — ни один тест/код не мутирует ОС. Коммит/PR — вне рабочего окна (08:00–19:00 МСК).

## 1. Permission-индекс и охват

- [x] 1.1 Модуль `exposure/` ; тип `InodeRecord { path, uid, gid, mode, acl, class }` и `PermissionIndex`.
- [x] 1.2 Walk охваченных корней: дефолт = security-relevant набор (расширить классификатор из
      `coverage.rs`); пропуск псевдо-ФС (`/proc`,`/sys`,`/dev`) и сетевых монтирований; не следовать
      симлинкам за пределы охвата. (M2-фикс: fstype-классификация маунтов `mounts.rs` — спуск в
      локальные сабмаунты, пропуск сети+псевдо, `skipped_mounts` notice; visited-guard dev/ino.)
- [x] 1.3 ACL на инод через переиспользование чтения POSIX ACL из `fileaccess.rs` (AclBackend).
      (best-effort per-path, чанки 256, без `-R`; `BestEffortRunner` — отсутствующий корень не роняет аудит.)
- [x] 1.4 Unit (tempdir-фикстуры): индекс строится по `--root`; псевдо-ФС/сетевые пропущены; режим/
      owner/gid/ACL прочитаны верно.

## 2. Access-check и reachability

- [x] 2.1 POSIX access-check `effective(record, principal) -> {r,w,x}`: uid0 short-circuit; owner→owner;
      ACL named-user→&mask; gid∈gids или ACL named-group→group-class&mask; иначе other.
- [x] 2.2 x-траверсия предков с мемоизацией по дереву каталогов: объект достижим ⇔ все предки дают `x`.
- [x] 2.3 Резолв принципала `name|uid` → uid+primary+supplementary (getgrouplist по локальным
      `/etc/passwd`,`/etc/group`); advisory-ограничение NSS/LDAP в доке модуля.
- [x] 2.4 Unit: файл 777 за дир-700-owned-root недостижим (не finding); доступ через дополнительную
      группу; named-user ACL; ACL-маска срезает group-запись; принципал по числовому uid.

## 3. Taxonomy, severity, remediation_class

- [x] 3.1 `Finding { principal, path, access, via, class, risk, severity, remediation_class, hint }`.
- [x] 3.2 Классификатор object-class (cron/systemd-unit/path-binary/sudoers/config/secret/
      setuid-binary/generic) — конфиг-список глобов с дефолтами.
- [x] 3.3 Деривация `severity` из class×risk (escalation на cron/sudoers/unit/path-binary=high;
      leak на secret=high; world-writable generic=low) и `risk` из access×class.
- [x] 3.4 `remediation_class`: source — чужой объект → `ambient` (+`chmod`/`setfacl` hint, без обещания
      авто-фикса); source — объект Census (managed-группа/свой file-access грант) → `in-model`
      (+«сузь декларацию»).
- [x] 3.5 Unit: эскалация на cron=high; leak секрета=high via other_bits; ambient hint без авто-фикса;
      in-model раздутая группа.

## 4. Режим expose + intended baseline

- [x] 4.1 `census audit expose --principal <name|uid>`: срез индекса access-eval'ом под принципал.
- [x] 4.2 Killer-фильтр: managed роль-учётка (из реестра `/var/lib/census/managed.toml`) → вычесть
      intended baseline (home + выданные каталогом пути); немэнэджед uid → сырой reachability.
- [x] 4.3 DAC-only пометка верхней границы в выводе (MAC не учтён).
- [x] 4.4 Unit: managed-учётке выданный грант вычтен, остаётся только лишний доступ; немэнэджед uid —
      без вычитания; пометка DAC-only присутствует.

## 5. Режим audit fs (posture-карта)

- [x] 5.1 `census audit fs`: principal-independent классы из индекса — world-writable в чувствительных
      деревьях; setuid/setgid инвентарь (+флаг writable); world-readable секреты; broad-group-writable
      (`users`/`staff` + настраиваемый список).
- [x] 5.2 Unit: world-writable cron в posture; записываемый setuid-бинарь с флагом writable (повышенная
      severity); world-readable секрет; principal не требуется.

## 6. CLI, охват-флаги, вывод, контракт

- [x] 6.1 Подкоманда `census audit` (`fs`/`expose`); флаги `--root PATH` (repeatable), `--full`,
      `--format text|json`; read-only инвариант (MUST NOT мутировать).
- [x] 6.2 Интерактивный выбор охвата на TTY без scope-флага (важное/полный/свои корни); без TTY —
      дефолтный охват без запроса.
- [x] 6.3 Код возврата: находки выше порога severity (дефолт high) → ненулевой; иначе 0.
- [x] 6.4 Вывод НЕ включает содержимое секрет-файлов (только путь/режим/метаданные).
- [x] 6.5 Golden CLI/JSON (schemars/clap) — стабильный контракт (`UPDATE_CONTRACT=1` для осознанной
      правки); конфиг scan-roots/secret-globs/broad-groups (комменты English, human-text → l10n).

## 7. Конфиг, доки, верификация

- [x] 7.1 TOML-конфиг охвата/классификаторов с дефолтами; строгий парс. (`exposure.toml`:
      scan_roots/secret_globs/broad_groups, deny_unknown_fields, `--config`, отсутствие файла→дефолты.
      L2-фикс: broad-group резолвится из реального /etc/group по имени. L1: schemars-golden
      `contract/exposure-report.schema.json`. L3: clap conflicts_with root/full.)
- [x] 7.2 README/доки: режимы, DAC-only оговорка, advisory NSS-ограничение, отчёт-как-чувствительный-
      артефакт. (README раздел + `examples/exposure.toml`.)
- [x] 7.3 Re-scan живого Astra: `census audit fs` и `audit expose` на реальной роль-учётке; убедиться,
      что reachability честна (нет ложняков «777 за закрытым каталогом»), read-only подтверждён.
      ПРОГНАНО 2026-06-29 на живом Astra Linux x86_64 (musl static-pie бинарь, cross rustc 1.85).
      `audit fs --root /etc --root /var/spool` (sudo) → 1 finding (world-readable `.pem`, high/leak/ambient,
      `chmod 640`-хинт), exit 1 (ненулевой как doctor). `audit expose --principal daemon` → «unmanaged» +
      DAC-нота присутствует; reachability честна: `/etc/shadow` (640 root:shadow) НЕ в выводе для daemon
      (недостижим → не finding). Read-only подтверждён эмпирически: флагнутый файл остался 644 (census НЕ
      chmod'ил), `/var/lib/census/` не создан (state не писался). Побочно: cross-build ловил `const fn` на
      `Vec::is_empty`/`len` (нативный toolchain свежее cross-образа) — расконстил 4 fn. Наблюдение: дефолтный
      secret-глоб `**/*.pem` ловит и публичные серты (/etc/ssl/certs snakeoil) → лёгкий шум, тюнится конфигом.
