# Tasks: file-access

Реализуется поверх `permission-catalog`. Срезами, TDD, `cargo test` + `cargo clippy --all-targets
-- -D warnings` зелёные, master-code-reviewer на срез. Коммит/PR — вне рабочего окна (08:00–19:00 МСК).

## Срез 1. Формат + резолв + shape
- [ ] 1.1 `FileGrant { path, access: Ro|Rw, recursive }` на `PermissionDef` (строгий парс под-таблицы,
      deny_unknown); валидация пути (абсолютный, без контрол/`..`).
- [ ] 1.2 `Shape` вывод (глоб→Pattern; конкретный файл→File; иначе Dir). `{param}`-подстановка +
      пост-валидация (reject инъекции), как sudo-параметры.
- [ ] 1.3 Резолв → `ResolvedFileGrant` (union по path, access=max(ro,rw), recursive=OR), provenance.
- [ ] 1.4 Unit: парс/валидация/shape/union/{param}/инъекция.

## Срез 2. SPI FileAccessBackend + AclBackend + gating
- [ ] 2.1 `FileAccessBackend` trait + `Capabilities`; `FileAccessError` (вкл. `Unsupported`).
- [ ] 2.2 `AclBackend`: dir-гранты `setfacl -R --physical` + default-ACL; revoke только `u:<acct>`;
      snapshot/restore `getfacl`/`setfacl --restore`; argv-only, идемпотентно.
- [ ] 2.3 `FakeBackend` (настраиваемые capabilities) для тестов.
- [ ] 2.4 Capability-gating: резолвер выбирает бэкенд по shape; нет покрывающего → `Unsupported`
      (fail-closed). Unit: Dir→Acl ок; File/Pattern без способного → отказ + сообщение.

## Срез 3. Apply / managed / откат
- [ ] 3.1 `ResolvedAccount.file_grants` + `ManagedAccount.file_grants` (serde default, round-trip).
- [ ] 3.2 `diff_fields` сравнивает file_grants (set-eq) → Update/revoke исчезнувшего.
- [ ] 3.3 Фаза apply (после sudoers, перед лимитами): backend.materialize/revoke; затрагиваемые пути
      в backup-set ДО снапшота; backend.snapshot перед мутацией; сбой → backend.restore.
- [ ] 3.4 Unit (FakeProvisioner+FakeBackend): материализация, отзыв, откат, идемпотентность.

## Срез 4. Coverage
- [ ] 4.1 `config`-класс покрыт по file-гранту (file/recursive-dir, ro/rw различать); отчёт —
      бэкенд+гарантия.
- [ ] 4.2 Знаменатель config → security-relevant набор (drop-in dirs + критичные пути + пути грантов).
- [ ] 4.3 Unit на coverage config-класса.

## Срез 5. CLI / doctor / risk
- [ ] 5.1 `compile`/`show` рендерят file-гранты (path, ro/rw, recursive, shape, бэкенд, риск).
- [ ] 5.2 `doctor` — ACL-дрейф (managed dir-грант пропал/изменён) → Warn.
- [ ] 5.3 lint: rw на root-эквивалентные пути / ro на секреты → escalation-маркер/предупреждение.

## Срез 6. Стартовый каталог + l10n + re-scan
- [ ] 6.1 Папочные file-гранты ключевым разрешениям: ssh-admin→`/etc/ssh` rw, pam-config→`/etc/pam.d`
      rw, audit-config→`/etc/audit` rw, log-read→`/var/log` ro recursive, ca-trust-admin→
      `/usr/local/share/ca-certificates` rw, journald-config→`/etc/systemd` rw (узко), и т.п.
- [ ] 6.2 l10n en/ru/zh (тексты не меняются — гранты структурны; новых id, скорее всего, нет).
- [ ] 6.3 Re-scan Astra: config-coverage > 0; убедиться в честном отчёте (dir-гранты покрывают).

## Срез 7. Контейнер
- [ ] 7.1 Реальный setfacl: `getfacl` показывает `u:role:rwX` + default-ACL на папке.
- [ ] 7.2 Rewrite-proof: новый файл в папке (создать+rename) наследует default-ACL → доступ цел.
- [ ] 7.3 ro=`r-X`/rw=`rwX`; откат при сбое фазы; отзыв снимает ТОЛЬКО `u:role` (чужая `u:other` цела).
- [ ] 7.4 File/Pattern грант без способного бэкенда → apply отказывает (fail-closed).

## Проверки
- [ ] 8.1 `cargo test` + `cargo clippy --all-targets -- -D warnings` зелёные.
- [ ] 8.2 master-code-reviewer; фикс CRITICAL/HIGH (setfacl как root — PwnKit/path-traversal/симлинки).
- [ ] 8.3 `openspec validate file-access --strict`.
- [ ] 8.4 Угроза-дельта (setfacl-мутация, SPI-загрузка `.so`) → threat-model §5.14 (tessera-ws).
