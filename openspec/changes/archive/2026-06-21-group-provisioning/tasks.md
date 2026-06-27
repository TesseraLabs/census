# Tasks: group-provisioning

## 1. Декларация + требуемый набор

- [x] 1.1 `Declaration`: `groups: Vec<GroupSpec>` (`#[serde(default)]`), `GroupSpec { name, gid: Option<u32> }`, строгий парсинг
- [x] 1.2 `required_groups(decl, resolved)` — union `payload.groups` всех ролей ∪ имена `[[group]]`; map name→Option<gid> из `[[group]]`
- [x] 1.3 Unit: union; пин gid берётся из `[[group]]`; группа без пина → None

## 2. Реестр managed-групп

- [x] 2.1 `state.rs`: managed-группы в реестре (`ManagedGroup { name, gid, from_version }`, секция `[[group]]` в managed.toml), `deny_unknown_fields`
- [x] 2.2 `SystemInspector`/Live: `group(name) -> Option<GroupFacts{gid}>` через getent group
- [x] 2.3 Unit: сериализация реестра групп; чтение getent group (Fake)

## 3. diff + GroupAction

- [x] 3.1 `plan.rs`: `GroupAction::{Create{name,gid}, Delete{name}}`; diff требуемое vs managed-группы+факт:
  отсутствует → Create; существует не в реестре → пропустить; в реестре и не требуется → Delete
- [x] 3.2 GID-пин конфликт (живой gid ≠ пин для существующей) → ошибка/находка
- [x] 3.3 `census plan` показывает группо-действия
- [x] 3.4 Unit: create/skip-foreign/delete-orphan; конфликт gid

## 4. Provisioner + порядок фаз

- [x] 4.1 `Provisioner` += `create_group(name, gid: Option<u32>)` (groupadd [-g]), `delete_group(name)` (groupdel); ShadowUtils + Fake
- [x] 4.2 `apply.rs`: фаза создания групп ДО учёток; удаление осиротевших групп ПОСЛЕ userdel
- [x] 4.3 Реестр (учётки+группы) пишется атомарно последним; group/gshadow уже в backup
- [x] 4.4 Unit (FakeProvisioner): порядок (group create до user create, group delete после user delete); конфликт gid → отказ до мутаций соответствующей фазы

## 5. doctor

- [x] 5.1 `doctor`: managed-группа пропала / GID разошёлся с реестром → Error (§4)
- [x] 5.2 Unit

## 6. Контейнер-интеграция (harness)

- [x] 6.1 Декларация с группой без пред-создания → apply создаёт группу + учётку с членством
- [x] 6.2 Роль теряет группу → осиротевшая managed-группа удаляется
- [x] 6.3 Пред-существующая чужая группа не удаляется
- [x] 6.4 GID-пин → заданный GID (getent group подтверждает)

## 7. Канон + ревью

- [x] 7.1 core-spec §3/§5 + authoring-packages.md §12: группы теперь создаются (убрать
  ограничение «должны существовать заранее»; описать `[[group]]`/пин GID)
- [x] 7.2 master-code-reviewer перед коммитом
