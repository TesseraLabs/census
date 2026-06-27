# Tasks: live-reconcile

## 1. Seam SessionSource + lazy-парсинг
- [x] 1.1 `LiveSessions { names: HashSet<String>, uids: HashSet<u32> }` + `SessionEntry`
      (lenient serde: `pam_user`, `uid`, прочее игнор).
- [x] 1.2 `trait SessionSource { fn live() -> Result<LiveSessions, SessionError> }`.
- [x] 1.3 `LiveSessionSource { path }`: read → parse → множества; `NotFound` ⇒ пустой Ok;
      IO/parse error ⇒ Err. Unit: формат `ActiveSession` с лишними полями, NotFound,
      битый JSON, матч по uid и по имени.
- [x] 1.4 `FakeSessionSource` для оркестратора.

## 2. Врезка в apply::run
- [x] 2.1 `ApplyInputs` получает `session_source: &dyn SessionSource` + `sessions_file: PathBuf`
      (для логирования пути).
- [x] 2.2 После group-diff, до anti-lockout: `live = session_source.live()?`. Если в плане есть
      `Action::Delete` и `live()` вернул Err (битый/нечитаемый реестр) — fail-closed (ApplyError),
      до snapshot/мутаций. Нет Delete ⇒ ошибку чтения игнорируем (нечего откладывать).
- [x] 2.3 Разбить deletes на executed/deferred по `name ∈ live.names || uid ∈ live.uids`.
      Изъять deferred из `plan.actions`. Лог-строка на каждую отложенную.
- [x] 2.4 `build_managed_set`: к целевому набору добавить deferred-учётки из `managed_now`
      с их прежним `from_version` (удержание владения).
- [x] 2.5 Идемпотентная ветка (`plan.is_empty()` после изъятия): не потерять deferred в managed;
      `registry_written` корректен (реестр уже содержит их).
- [x] 2.6 `ApplyReport`: поле `deferred_deletes: Vec<String>` (или счётчик) для CLI/exit-code.

## 3. CLI wiring
- [x] 3.1 Флаг `--sessions-file` (дефолт `/run/tessera/sessions.json`).
- [x] 3.2 Собрать `LiveSessionSource`, прокинуть в `ApplyInputs`.
- [x] 3.3 Сводка: «применено N, отложено M»; exit nonzero при M>0 (код, отличимый от ошибки фазы).

## 4. Контейнерный тест
- [x] 4.1 Сценарий: создать роль-учётку, сэмулировать sessions.json с её uid/именем, apply с
      Delete → userdel пропущен, учётка жива (`getent passwd`), реестр держит её, exit nonzero.
- [x] 4.2 Повтор без sessions.json → учётка доудалена, exit 0.
- [x] 4.3 Регресс: битый sessions.json + план с Delete → apply fail-closed, ОС не изменена.

## 5. Проверки
- [x] 5.1 `cargo test` (unit + контейнер) зелёные, `cargo clippy -- -D warnings` чисто.
- [x] 5.2 master-code-reviewer; починить CRITICAL/HIGH.
- [x] 5.3 `openspec validate live-reconcile --strict`.
