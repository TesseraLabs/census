# Design: group-grants

Полный дизайн (ход обсуждения, инвариант A, adoption-семантика, граница LDAP-вложенности) —
internal `specs/2026-06-22-group-grants-adoption-design.md`. Здесь — привязка к коду
(public-safe).

## Декларация

```toml
[[role_account]]                  # СУЩЕСТВУЕТ: Created (role+uid)
role = "netops"
uid  = 9001

[[role_account]]                  # НОВОЕ: Adopted существующий юзер
role  = "infra-admin"
user  = "alice"                   # взаимоисключающе с uid; adopt=true обязателен
adopt = true

[[group]]                         # объект группы: существование + provenance + члены
name    = "ops"
gid     = 8020                    # gid и нет adopt → Created
members = ["netops", "alice"]     # Created: любые юзеры

[[group]]
name    = "wheel"
adopt   = true                    # → Adopted; gid запрещён; чужой состав не трогаем
members = ["netops"]              # Adopted: ТОЛЬКО managed роль-учётки

[[role_group]]                    # привязка гранта роль→группа (many-to-one)
role  = "infra-admin"
group = "wheel"
```

Валидация (deny_unknown_fields): `user`⇒`adopt=true`&&нет `uid`; `uid`⇒нет `user`;
`adopt=true` без `user` — ошибка. `[[group]].adopt=true`⇒`gid` запрещён. Adopted-члены ⊆
managed роль-учётки (чужой юзер в чужую группу = нарушение инварианта A → ошибка).
`[[role_group]].group` обязан ссылаться на объявленный `[[group]]`.

## Типы / стейт

```rust
enum Provenance { Created, Adopted }
struct GroupBaseline { gid: u32, members: Vec<String> }
struct ManagedGroup {
    name: String, gid: u32, provenance: Provenance,
    members_added: Vec<String>,           // кого добавил Census (хирургическое снятие)
    bound_roles: Vec<String>,
    adopt_baseline: Option<GroupBaseline>, // снапшот при adopt; None для Created
}
// ManagedAccount += provenance: Provenance, adopt_baseline: Option<AccountBaseline>
```

`#[serde(default)]` на новых полях — round-trip со старым стейтом.

## Резолв

- `[[role_group]]` → роль раскрывается тем же резолвером каталога (permissions→примитивы), но
  материализуется в group-формы. Под-примитив `groups` (вступление) на group-цели — warn+skip
  (нет локальной вложенности; LDAP-вложенность работает прозрачно через `%group`/`g:group`).
- Provenance выводится: `[[group]].adopt`/`[[role_account]].adopt` → Adopted; иначе Created.

## OS-примитивы (group-цель)

| Примитив | Форма |
|---|---|
| sudo | `/etc/sudoers.d/census-grp-<g>` → `%<g> ALL=(root) NOPASSWD: <cmds>` (тот же escaper + `visudo -c`) |
| ACL | AclBackend group-principal: `setfacl -m g:<g>:<r-X\|rwX>` + default-ACL `-d` (папки); revoke `-x g:<g>`. Зеркало `u:account`; та же capability-gating |
| limits | НЕ материализуются — Census не пишет `limits.d` ни для учёток, ни для групп (резолв для отчётов, enforcement вне периметра). Group-грант симметричен учётке. |

## Apply / план / откат

- Plan diff (группы): Create / Adopt / Release / Delete + attach/detach. Триггер release-vs-
  delete — по СОХРАНЁННОМУ provenance, не по форме декларации.
- Порядок: группы → учётки → sudoers(`%group`) → file-access(`g:group`) → limits(`@group`).
  Baseline-снапшот и затрагиваемые пути → backup-set ДО мутации; сбой фазы → restore.
- Anti-lockout/trust: `%group`-фрагменты под теми же guard'ами, что account-sudoers.

## Adoption / release

- **adopt:** читаем gid+члены (или факт существования юзера) → `adopt_baseline`; применяем гранты.
- **release** (отсутствует в декларации, stored=Adopted): снять `census-grp-*`/ACL/limits +
  `members_added`, восстановить baseline; НЕ `groupdel/userdel`.
- **delete** (отсутствует, stored=Created): `groupdel`/`userdel`.

## Coverage / which-grants / doctor / risk

- which-grants: `via %group sudoers`/`via g:group ACL` с именем группы и риском.
- coverage: класс `group` покрыт при наличии привязки (не только membership).
- doctor: adopted-baseline drift (gid/фрагмент/наш член) → Warn; created-группа пропала → Warn.
- risk: групповой грант = наследуют все члены (вкл. LDAP-вложенных) → escalation-поверхность;
  lint/show/coverage подсвечивают.

## Безопасность (дельта threat-model §5.14)

Новые мутации `gpasswd`/`%group`/`g:group`/`@group` — argv-only, санитайз, `visudo -c`.
Adoption-захват: baseline + хирургическое снятие (только свои члены/артефакты), никогда не
`groupdel/userdel` adopted. `%group` на широкую (adopted) группу раздаёт права множеству —
risk/lint обязаны подсвечивать. fail-closed на невалидную декларацию.

## Тестирование

- Unit: парс/валидация (`user`+`uid`, `adopt`+`gid`, чужой член в adopted, `role_group`→
  необъявленная группа); резолв роли на group-цель + `groups`-warn-skip; provenance-вывод;
  diff Create/Adopt/Release/Delete; ACL group-principal args; baseline snapshot/restore.
- Контейнер: реальный `%group` sudoers (`visudo -c`); `g:group` ACL (getfacl показывает
  `g:role:rwX` + default-ACL, новый файл наследует); `@group` limits; adopt существующей
  группы → baseline записан; release → baseline восстановлен, группа жива, чужой член цел;
  created → groupdel; невалидная декларация → отказ до мутаций.
