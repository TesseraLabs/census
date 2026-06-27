# Design: file-access

Полный дизайн (механизм, ход обсуждения, граница МКЦ, обоснование SPI/dir-only) — internal
`specs/2026-06-22-file-access-primitive-design.md`. Здесь — привязка к коду (public-safe).

## Типы
```rust
enum Access { Ro, Rw }
enum Shape { Dir, File, Pattern }            // выводится из пути (глоб → Pattern; есть basename-файл → File; иначе Dir)
struct FileGrant { path: String, access: Access, recursive: bool }            // на PermissionDef (deny_unknown под-таблица)
struct ResolvedFileGrant { path, access, recursive, shape, sources: Vec<SourcedFrom> }  // резолв: union по path, access=max, recursive=OR
struct Capabilities { dir: bool, per_path: bool, pattern: bool, realtime: bool, rewrite_proof: bool }
trait FileAccessBackend {
    fn name(&self) -> &str;
    fn capabilities(&self) -> Capabilities;
    fn materialize(&mut self, account: &str, grants: &[ResolvedFileGrant]) -> Result<(), FileAccessError>;
    fn revoke(&mut self, account: &str, grant: &ResolvedFileGrant) -> Result<(), FileAccessError>;
    fn snapshot(&mut self, paths: &[&Path]) -> Result<(), FileAccessError>;
    fn restore(&mut self) -> Result<(), FileAccessError>;
}
```

## AclBackend (open, built-in)
- `capabilities { dir:true, per_path:false, pattern:false, realtime:false, rewrite_proof:true }`.
- materialize (Dir-грант): `setfacl -R --physical -m u:<acct>:<r-X|rwX> <dir>` + `setfacl -d -R
  --physical -m u:<acct>:<…> <dir>` (default-ACL). `--physical` — не следовать симлинкам.
- revoke: `setfacl -R --physical -x u:<acct> <dir>` (+ default). Только `u:<acct>` запись; чужие
  (`u:other`/`g:`)/владелец/режим не трогает.
- snapshot/restore: `getfacl --absolute-names -R <path>` в rollback-каталог; `setfacl --restore`.
- argv-only (без shell). Идемпотентно (повторный `-m` той же записи — no-op по содержанию).

## Резолвер + capability-gating
- `resolve_file_grants(role) -> Vec<ResolvedFileGrant>` (union, shape). Для каждого гранта выбрать
  бэкенд, чьи capabilities покрывают shape (Dir→`dir`; File→`per_path`; Pattern→`pattern`).
- Нет покрывающего бэкенда → `FileAccessError::Unsupported { path, shape, reason }` → apply/compile
  fail-closed ДО мутаций, с подсказкой (расширить File→Dir или установить бэкенд). `compile --lint`
  отдаёт это как ошибку (ненулевой код).
- FakeBackend (тесты) с настраиваемыми capabilities — проверять и материализацию, и gating-отказ.

## Apply / managed / откат
- `ResolvedAccount.file_grants`, `ManagedAccount.file_grants` (`#[serde(default)]`). `diff_fields`
  set-eq по (path,access,recursive) → Update; исчезнувший грант → revoke. Реестр — авторитет снятия.
- Фаза apply: после sudoers, перед лимитами. Затрагиваемые пути → backup-set ДО снапшота;
  `backend.snapshot` перед мутацией; при сбое фазы — `backend.restore` (как full-file backup, R2).

## Coverage
- `config`-объект покрыт ⇔ путь == грант ИЛИ под recursive-Dir-грантом; ro/rw различать. Отчёт:
  бэкенд+гарантия. Знаменатель config = security-relevant (drop-in dirs + критичные пути + пути
  из file-грантов), не все conffiles.

## Безопасность
- Путь: абсолютный, без контрол-символов/`..`; `{param}`-подстановка с пост-валидацией (как sudo-
  параметры). `setfacl -R --physical` — без выхода по симлинкам. fail-closed на невалидный путь/
  неподдержанный грант. Реестр — авторитет снятия ACL (Census не сносит чужие записи).
- rw на root-эквивалентные пути / ro на секреты → escalation-capable (lint/doctor предупреждает).

## Тестирование
- Unit: парс `[[file]]` (deny_unknown, валидация, ro/rw, recursive); shape-вывод (dir/file/глоб);
  резолв union+provenance+max-access; `{param}` + инъекция-reject; diff/отзыв; capability-gating
  (Dir→ок через Acl; File/Pattern без способного бэкенда → Unsupported); coverage config по гранту.
- Контейнер: реальный setfacl — getfacl показывает `u:role:rwX` + default-ACL; **новый файл в папке
  наследует** (rewrite-через-rename НЕ теряет доступ); ro=`r-X`/rw=`rwX`; откат при сбое фазы; отзыв
  снимает ТОЛЬКО свою запись (чужая `u:other`/`g:` цела); File/Pattern грант без бэкенда → отказ.
