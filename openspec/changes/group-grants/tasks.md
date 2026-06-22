# Tasks: group-grants

Реализуется поверх `permission-catalog` + `file-access`. Срезами, TDD, `cargo test` +
`cargo clippy --all-targets -- -D warnings` зелёные, master-code-reviewer на срез. Коммит/PR —
вне рабочего окна (08:00–19:00 МСК).

## Срез 1. Декларация + валидация
- [x] 1.1 `[[role_group]] { role, group }` (строгий парс, deny_unknown).
- [x] 1.2 `[[group]]` += `adopt: bool`, `members: Vec<String>`; `[[role_account]]` += `user`,
      `adopt`.
- [x] 1.3 Валидация: `user`⇒`adopt=true`&&нет `uid`; `uid`⇒нет `user`; `adopt` без `user` —
      ошибка; `[[group]].adopt=true`⇒`gid` запрещён; adopted-члены ⊆ managed роль-учётки;
      `role_group.group` ссылается на объявленный `[[group]]`; дедуп (role,group).
- [x] 1.4 Unit: каждый кейс валидации (ок и отказ).

## Срез 2. Provenance + резолв роли на группу
- [x] 2.1 `Provenance::{Created,Adopted}`; вывод из `adopt`.
- [x] 2.2 Резолв `[[role_group]]` → group-формы примитивов (sudo/file/limits); под-примитив
      `groups` → warn+skip (с диагностикой «не применимо к group-цели»).
- [x] 2.3 Unit: резолв group-цели, union нескольких ролей на группу, `groups`-warn-skip,
      provenance-вывод.

## Срез 3. Стейт
- [x] 3.1 `ManagedGroup { name, gid, provenance, members_added, bound_roles, adopt_baseline }`
      + `ManagedAccount` += `provenance`/`adopt_baseline` (`#[serde(default)]`, round-trip).
- [x] 3.2 Unit: сериализация/десериализация, совместимость со старым стейтом.

## Срез 4. План (diff)
- [x] 4.1 diff групп: Create / Adopt / Release / Delete + attach/detach грантов.
- [x] 4.2 Триггер release-vs-delete по СОХРАНЁННОМУ provenance (не по форме декларации).
- [x] 4.3 Unit: каждый переход (создать/adopt/release/delete; добавить/снять привязку).

## Срез 5. Apply / откат
- [x] 5.1 Фазы: группы (create/adopt) → учётки → sudoers(`%group`) → file-access(`g:group`) →
      limits(`@group`). Порядок и баррьеры.
- [x] 5.2 adopt: снять baseline (gid+члены) ДО мутаций → backup-set; release → восстановить
      baseline + снять свои члены/артефакты; created delete → `groupdel`/`userdel`.
- [x] 5.3 `%group` sudoers: `visudo -c`, anti-lockout, trust — те же guard'ы, что account.
- [x] 5.4 AclBackend group-principal: `setfacl -m g:<g>` + default-ACL; revoke `-x g:<g>`;
      capability-gating без изменений.
- [~] 5.5 limits `@group`: НЕ реализовано намеренно — Census не материализует `limits.d` ни для
      учёток, ни для групп (резолв для отчётов, enforcement лимитов вне периметра). Симметрия с учёткой.
- [x] 5.6 Unit (FakeProvisioner): материализация/откат/идемпотентность каждой формы.

## Срез 6. Coverage / which-grants / doctor / risk
- [x] 6.1 which-grants: `via %group`/`via g:group` с именем группы и риском.
- [x] 6.2 coverage: класс `group` покрыт при привязке.
- [x] 6.3 doctor: adopted-baseline drift (gid/фрагмент/наш член) → Warn; created пропала → Warn.
- [x] 6.4 risk/lint: групповой escalation-capable грант подсвечен (наследуют все члены).
- [x] 6.5 Unit на каждый отчёт.

## Срез 7. Контейнер
- [x] 7.1 `%group` sudoers проходит `visudo -c`; член группы получает команду.
- [x] 7.2 `g:group` ACL: getfacl показывает `g:role:rwX` + default-ACL; новый файл наследует.
- [~] 7.3 `@group` limits — снят из объёма (limits не материализуются, см. 5.5).
- [x] 7.4 adopt существующей группы → baseline записан; release → baseline восстановлен,
      группа жива, чужой pre-existing член цел.
- [x] 7.5 created группа → `groupdel` на удаление; adopted НИКОГДА не удаляется.
- [x] 7.6 Невалидная декларация (user+uid / adopt+gid / чужой член в adopted / битый `%group`)
      → apply отказывает до мутаций.

## Проверки
- [x] 8.1 `cargo test` + `cargo clippy --all-targets -- -D warnings` зелёные.
- [x] 8.2 master-code-reviewer; фикс CRITICAL/HIGH (gpasswd/setfacl/%group как root —
      injection, симлинки, anti-lockout, adoption-захват).
- [x] 8.3 `openspec validate group-grants --strict`.
- [ ] 8.4 Угроза-дельта (gpasswd/%group/g:group, adoption-захват) → threat-model §5.14 (tessera-ws).
      ОТЛОЖЕНО (follow-up, не блокирует реализацию).
