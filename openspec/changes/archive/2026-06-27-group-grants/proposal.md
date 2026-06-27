# Change: group-grants

## Why

До сих пор permission'ы материализуются только на роль-**учётку**: sudoers `census-<role>`,
ACL `u:<account>`, limits — всё пер-аккаунт. Нужны два связанных умения: (а) выдавать права
Unix-**группе** (все её члены, включая эффективно-вложенных из LDAP, наследуют грант) и
(б) различать объекты, которые Census создал, от уже существующих на системе, и уметь брать
существующие группы/юзеров под управление (adopt) и отпускать обратно (release), не разрушая
их. Полный дизайн и обоснование: internal `specs/2026-06-22-group-grants-adoption-design.md`.

Ключевые решения: единая provenance-модель (`Created | Adopted`) на учётках И группах;
привязка роли на группу через `[[role_group]]` (many-to-one); инвариант A — Census мутирует
существование/чужой состав ТОЛЬКО для Created-объектов, для Adopted ставит/снимает лишь свои
гранты и своих добавленных членов, release возвращает к baseline (тот же принцип, что у
file-access ACL: реестр — авторитет снятия).

## What Changes

- **Декларация**: новый `[[role_group]] { role, group }` (привязка гранта роли к группе);
  `[[group]]` расширяется полями `adopt`/`members`; `[[role_account]]` — полями `user`/`adopt`
  (adoption существующего юзера). Строгая валидация (взаимоисключения user/uid, adopt/gid;
  правило членов created vs adopted).
- **Provenance-модель**: `ManagedGroup`/`ManagedAccount` несут `provenance: Created|Adopted`,
  `adopt_baseline` (снапшот gid+члены при adopt) и `members_added` (кого добавил Census).
- **Группа-цель примитивов**: sudo → `%group` (`/etc/sudoers.d/census-grp-<g>`); file-access
  ACL → `g:group` (AclBackend, зеркало `u:account`, та же default-ACL/capability-gating);
  limits → `@group` (`/etc/security/limits.d/census-grp-<g>.conf`). Под-примитив `groups`
  (вступление в группу) на group-цели — warn+skip (локальной вложенности нет).
- **Adoption/release**: adopt снимает baseline; release (объект/привязка исчезли, stored
  provenance=Adopted) снимает свои гранты + своих членов, возвращает к baseline, сущность
  жива; delete (provenance=Created) — полное снятие. Триггер ветвится по сохранённому
  provenance, не по форме декларации.
- **Coverage/which-grants/doctor/risk**: групповые гранты в отчётах (`via %group`/`g:group`);
  group-объект покрыт при наличии привязки; adopted-baseline drift → Warn; групповой грант с
  escalation-capable permission подсвечивается (наследуют все члены).

## Impact

- Affected specs: новая capability `group-grants` (расширяет provisioning + permission-catalog
  + file-access).
- Affected code (Rust, `census`): declaration.rs (`[[role_group]]`, adopt/members/user +
  валидация), model.rs/rolestore.rs (резолв роли на group-цель, provenance), state.rs
  (`ManagedGroup`/`ManagedAccount` + provenance/baseline/members_added), plan.rs (diff
  Create/Adopt/Release/Delete), apply.rs (фазы групп, `%group`/`@group`, baseline в backup-set,
  откат), fileaccess.rs (AclBackend group-principal `g:group`), coverage.rs/cli.rs/doctor.rs
  (отчёты, drift, risk).
- Зависит от `permission-catalog` и `file-access`. Граница open/closed не сдвигается: фича
  целиком на открытом ядре, новых signed-`.so` не вводит. Новые типы мутации (`gpasswd`,
  `%group`, `g:group`, `@group`) + adoption-захват — угроза-дельта threat-model §5.14.
- fail-closed: невалидная декларация (user+uid, adopt+gid, чужой юзер в adopted-члены, битый
  `%group`) → отказ до мутаций.
