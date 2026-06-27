# group-grants Specification

## Purpose
TBD - created by archiving change group-grants. Update Purpose after archive.
## Requirements
### Requirement: Привязка роли к группе

Декларация ДОЛЖНА (MUST) уметь объявлять `[[role_group]] { role, group }` — привязку грантов
роли к Unix-группе (many-to-one: на одну группу несколько ролей). Поле `group` ДОЛЖНО (MUST)
ссылаться на группу, объявленную в `[[group]]`. Парсинг ДОЛЖЕН (MUST) быть строгим
(`deny_unknown_fields`); дубли `(role, group)` ДОЛЖНЫ (MUST) дедуплицироваться.

#### Scenario: Роль привязана к группе
- **WHEN** декларация несёт `[[role_group]] role="infra-admin" group="wheel"` и `[[group]] name="wheel"`
- **THEN** резолв даёт группе все примитивы роли в group-формах с provenance

#### Scenario: Привязка к необъявленной группе отвергается
- **WHEN** `[[role_group]].group` указывает на имя без соответствующего `[[group]]`
- **THEN** валидация декларации отвергает запись с диагностикой

### Requirement: Provenance объектов (Created и Adopted)

Каждый управляемый объект (группа и учётка) ДОЛЖЕН (MUST) нести provenance `Created` или
`Adopted`. `[[group]].adopt = true` и `[[role_account]].adopt = true` ДОЛЖНЫ (MUST) давать
`Adopted`; иначе `Created`. Валидация ДОЛЖНА (MUST) отвергать противоречивые формы:
`[[role_account]]` с `user` обязан иметь `adopt = true` и не иметь `uid`; с `uid` — не иметь
`user`; `adopt = true` без `user` — ошибка; `[[group]].adopt = true` запрещает `gid`.

#### Scenario: Adoption существующего юзера
- **WHEN** `[[role_account]] role="infra-admin" user="alice" adopt=true`
- **THEN** объект помечается Adopted и привязывается к существующему юзеру без создания учётки

#### Scenario: Противоречивая декларация отвергается
- **WHEN** `[[role_account]]` несёт одновременно `user` и `uid`, или `[[group]]` — `adopt=true` и `gid`
- **THEN** валидация отвергает до любых мутаций

### Requirement: Инвариант владения для Adopted-объектов

Census НЕ ДОЛЖЕН (MUST NOT) создавать или удалять Adopted-группу/юзера и НЕ ДОЛЖЕН (MUST NOT)
менять их чужой (pre-existing) состав. На Adopted-объект Census ДОЛЖЕН (MUST) ставить и
снимать ТОЛЬКО свои гранты (`census-grp-*` sudoers, `g:group` ACL, `@group` limits) и своих
добавленных членов. Члены, добавляемые в Adopted-группу, ДОЛЖНЫ (MUST) быть только
Census-managed роль-учётками.

#### Scenario: Чужой юзер в adopted-группу отвергается
- **WHEN** `[[group]] name="wheel" adopt=true members=["external-user"]`, где external-user не управляется Census
- **THEN** валидация отвергает запись (нарушение инварианта владения)

#### Scenario: Adopted-группа не удаляется
- **WHEN** Adopted-группа исчезает из декларации
- **THEN** Census снимает свои гранты и своих членов, но НЕ выполняет `groupdel`

### Requirement: Материализация грантов на группу

Грант на группу ДОЛЖЕН (MUST) материализоваться в group-формы: sudo — фрагментом
`/etc/sudoers.d/census-grp-<g>` с правилом `%<g>` (через `visudo -c`, с тем же санитайзингом и
anti-lockout/trust-гардами, что у учёток); файловый доступ — записью `g:<group>` через
AclBackend (с default-ACL для папок, той же capability-gating). Под-примитив вступления в группу
(`groups`) на group-цели ДОЛЖЕН (MUST) пропускаться с предупреждением (локальной вложенности
нет). Лимиты НЕ материализуются (Census не пишет `limits.d` ни для учёток, ни для групп — они
резолвятся для отчётов, но enforcement лимитов вне периметра; group-грант симметричен учётке).

#### Scenario: Групповой sudo-грант применён
- **WHEN** роль с sudo-командами привязана к группе, и apply исполняется
- **THEN** пишется `census-grp-<g>` с `%<g> ... NOPASSWD: <cmds>`, проходящий `visudo -c`

#### Scenario: Групповой файловый грант через ACL
- **WHEN** роль с папочным rw-file-грантом привязана к группе при установленном AclBackend
- **THEN** на папку ставится `g:<group>` ACL + default-ACL; чужие записи не затрагиваются

### Requirement: Adoption-baseline и release к исходному состоянию

При adopt Census ДОЛЖЕН (MUST) снять снапшот baseline (gid и члены группы / факт существования
юзера) в реестр. При release (объект или привязка исчезли из декларации, а сохранённый
provenance — Adopted) Census ДОЛЖЕН (MUST) снять все свои гранты и своих добавленных членов и
вернуть объект к baseline, не удаляя сущность. Триггер release-vs-delete ДОЛЖЕН (MUST)
определяться сохранённым provenance, а не формой декларации.

#### Scenario: Release возвращает к baseline
- **WHEN** Adopted-группа с записанным baseline исчезает из декларации
- **THEN** Census убирает свои члены/гранты и восстанавливает baseline (gid и pre-existing члены целы), группа жива

#### Scenario: Created удаляется полностью
- **WHEN** Created-группа исчезает из декларации
- **THEN** Census выполняет `groupdel` (полное снятие)

### Requirement: Учёт групповых грантов в отчётах

`census catalog which-grants` ДОЛЖЕН (MUST) показывать групповые гранты (`via %group sudoers` /
`via g:group ACL`) с именем группы и классом риска. `census catalog coverage` ДОЛЖЕН (MUST)
считать объект класса `group` покрытым при наличии привязки роли к нему. `census doctor`
ДОЛЖЕН (MUST) сообщать о дрейфе adopted-baseline (изменённый gid, снятый фрагмент, выбывший
наш член) предупреждением.

#### Scenario: which-grants показывает групповой грант
- **WHEN** к группе привязан грант и выполняется `which-grants <cmd-or-path>`
- **THEN** в выводе есть строка с группой, механизмом (%group/g:group) и риском

#### Scenario: Дрейф adopted-baseline замечен
- **WHEN** у adopted-группы кто-то изменил gid или удалил `census-grp-*` фрагмент
- **THEN** `doctor` выдаёт предупреждение о дрейфе

