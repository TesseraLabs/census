# Tasks: file-access

Реализуется поверх `permission-catalog`. Срезами, TDD, `cargo test` + `cargo clippy --all-targets
-- -D warnings` зелёные, master-code-reviewer на срез. Коммит/PR — вне рабочего окна (08:00–19:00 МСК).

## Срез 1. Формат + резолв + shape
- [x] 1.1 `FileGrant { path, access: Ro|Rw, recursive }` на `PermissionDef` (строгий парс под-таблицы,
      deny_unknown); валидация пути (абсолютный, без контрол/`..`).
- [x] 1.2 `Shape` вывод (глоб→Pattern; конкретный файл→File; иначе Dir). `{param}`-подстановка +
      пост-валидация (reject инъекции), как sudo-параметры.
- [x] 1.3 Резолв → `ResolvedFileGrant` (union по path, access=max(ro,rw), recursive=OR), provenance.
- [x] 1.4 Unit: парс/валидация/shape/union/{param}/инъекция.

## Срез 2. SPI FileAccessBackend + AclBackend + gating
- [x] 2.1 `FileAccessBackend` trait + `Capabilities`; `FileAccessError` (вкл. `Unsupported`).
- [x] 2.2 `AclBackend`: dir-гранты `setfacl -R --physical` + default-ACL; revoke только `u:<acct>`;
      snapshot/restore `getfacl`/`setfacl --restore`; argv-only, идемпотентно.
- [x] 2.3 `FakeBackend` (настраиваемые capabilities) для тестов.
- [x] 2.4 Capability-gating: резолвер выбирает бэкенд по shape; нет покрывающего → `Unsupported`
      (fail-closed). Unit: Dir→Acl ок; File/Pattern без способного → отказ + сообщение.

## Срез 3. Apply / managed / откат
- [x] 3.1 `ResolvedAccount.file_grants` + `ManagedAccount.file_grants` (serde default, round-trip).
- [x] 3.2 `diff_fields` сравнивает file_grants (set-eq) → Update/revoke исчезнувшего.
- [x] 3.3 Фаза apply (после sudoers, перед лимитами): backend.materialize/revoke; затрагиваемые пути
      в backup-set ДО снапшота; backend.snapshot перед мутацией; сбой → backend.restore.
- [x] 3.4 Unit (FakeProvisioner+FakeBackend): материализация, отзыв, откат, идемпотентность.

## Срез 4. Coverage
- [x] 4.1 `config`-класс покрыт по file-гранту (file/recursive-dir, ro/rw различать); отчёт —
      бэкенд+гарантия.
- [x] 4.2 Знаменатель config → security-relevant набор (drop-in dirs + критичные пути + пути грантов).
- [x] 4.3 Unit на coverage config-класса.

## Срез 5. CLI / doctor / risk
- [x] 5.1 `compile`/`show` рендерят file-гранты (path, ro/rw, recursive, shape, бэкенд, риск).
- [x] 5.2 `doctor` — ACL-дрейф (managed dir-грант пропал/изменён) → Warn.
- [x] 5.3 lint: rw на root-эквивалентные пути / ro на секреты → escalation-маркер/предупреждение.

## Срез 6. Стартовый каталог + l10n + re-scan
- [x] 6.1 Папочные file-гранты ключевым разрешениям: ssh-admin→`/etc/ssh` rw, pam-config→`/etc/pam.d`
      rw, audit-config→`/etc/audit` rw, log-read→`/var/log` ro recursive, ca-trust-admin→
      `/usr/local/share/ca-certificates` rw, journald-config→`/etc/systemd` rw (узко), и т.п.
- [x] 6.2 l10n en/ru/zh (тексты не меняются — гранты структурны; новых id, скорее всего, нет).
- [~] 6.3 Re-scan Astra: config-coverage > 0; убедиться в честном отчёте (dir-гранты покрывают).
      ОТЛОЖЕНО — нужен прогон на Astra VM (стартовый каталог file-грантов 6.1 готов; верификация на живой ФС — отдельный VM-проход).

## Срез 7. Контейнер
ОТЛОЖЕНО — реальный `setfacl`/`getfacl`-E2E нужен в контейнере/Astra VM (docker недоступен в текущей среде).
Unit-эквиваленты (FakeBackend: materialize/revoke/откат/идемпотентность; `route_grants` fail-closed) зелёные и
покрывают логику; ниже — проверка живого ядра ACL отдельным прогоном.
- [~] 7.1 Реальный setfacl: `getfacl` показывает `u:role:rwX` + default-ACL на папке.
- [~] 7.2 Rewrite-proof: новый файл в папке (создать+rename) наследует default-ACL → доступ цел.
- [~] 7.3 ro=`r-X`/rw=`rwX`; откат при сбое фазы; отзыв снимает ТОЛЬКО `u:role` (чужая `u:other` цела).
- [~] 7.4 File/Pattern грант без способного бэкенда → apply отказывает (fail-closed). [unit-проверено `route_grants`; контейнер-форма отложена]

## Проверки
- [x] 8.1 `cargo test` зелёные (829, 0 failed); `cargo clippy --all-targets --locked` deny-tier чист
      (two-tier `[lints]`; `-D warnings` НЕ применять — ломает two-tier).
- [x] 8.2 master-code-reviewer (нет CRITICAL); фикс HIGH H1 (`revoke` гонял `setfacl -R` без symlink-guard
      → TOCTOU out-of-tree) + MEDIUM M1 (`getfacl`-снапшот без `--physical` + без symlink-guard) — общий
      `grant_root_is_symlink` на materialize/revoke/snapshot; + L1 (lint flag `ro` host-keys `/etc/ssh`),
      L2 (убрана 3-я копия `path_at_or_under`). Фикс верифицирован повторным ревью. Follow-up (accepted):
      L3 (route_grants single-backend dispatch), L4 (doctor drift не покрывает `g:group`).
- [x] 8.3 `openspec validate file-access --strict`.
- [x] 8.4 Угроза-дельта (setfacl-мутация, SPI-загрузка `.so`) → threat-model §5.14 (tessera-ws):
      CN10 (setfacl overbroad/симлинк — обновлён: symlink-корень блокируется на всех 3 root-операциях),
      CN11 (молча-слабый ACL → cap-gating fail-closed), CN12 (неподписанный backend-`.so`).
