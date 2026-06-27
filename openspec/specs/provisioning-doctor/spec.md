# provisioning-doctor Specification

## Purpose
TBD - created by archiving change provisioning-doctor. Update Purpose after archive.
## Requirements
### Requirement: doctor read-only диагностика

`census doctor` ДОЛЖЕН (MUST) выполнять только чтение и НЕ ДОЛЖЕН (MUST NOT) мутировать ни
один объект ОС или реестр. При обнаружении нарушения инварианта недостижимости (§8) или
целостности реестра (§4) `doctor` ДОЛЖЕН (MUST) завершаться ненулевым кодом; при чистом
результате или только предупреждениях — нулевым.

#### Scenario: Чистая система
- **WHEN** все managed роль-учётки недостижимы и реестр сходится с фактом
- **THEN** doctor печатает отсутствие ошибок и возвращает 0, ничего не меняя

#### Scenario: Нарушение → ненулевой код
- **WHEN** doctor находит хотя бы одно нарушение §8 или §4
- **THEN** doctor печатает находку и возвращает ненулевой код

### Requirement: Проверка недостижимости роль-учёток

`doctor` ДОЛЖЕН (MUST) для каждой managed роль-учётки проверять: пароль заблокирован (поле
shadow начинается с `!` или `*`) и отсутствует `~/.ssh/authorized_keys`. Разблокированный
пароль или наличие authorized_keys у managed роль-учётки ДОЛЖНЫ (MUST) давать находку уровня
Error. Полный анализ PAM-стека не требуется (advisory-ограничение задокументировано).

#### Scenario: Разблокированный пароль роль-учётки
- **WHEN** у managed роль-учётки пароль не заблокирован
- **THEN** doctor выдаёт Error и возвращает ненулевой код

#### Scenario: Появились authorized_keys
- **WHEN** у managed роль-учётки появился `~/.ssh/authorized_keys`
- **THEN** doctor выдаёт Error и возвращает ненулевой код

### Requirement: Целостность маркера managed

`doctor` ДОЛЖЕН (MUST) сверять реестр managed с фактом: запись реестра без живой учётки,
расхождение uid/shell/групп, а также живая учётка с GECOS-меткой Census, но без записи в
реестре, — каждое ДОЛЖНО (MUST) давать Error. Авторитетом ДОЛЖЕН (MUST) служить реестр, не
GECOS-метка.

#### Scenario: Поддельная GECOS-метка
- **WHEN** на устройстве есть учётка с GECOS-меткой Census, которой нет в реестре managed
- **THEN** doctor выдаёт Error (возможная подделка), возвращает ненулевой код

#### Scenario: Managed-объект пропал
- **WHEN** запись реестра ссылается на учётку, которой больше нет в системе
- **THEN** doctor выдаёт Error

### Requirement: Предупреждение anti-lockout

`doctor` ДОЛЖЕН (MUST) предупреждать (Warn, без ненулевого кода), если не осталось ни одной
login-способной учётки вне managed-набора (потенциальный lockout при отказе cert-пути).

#### Scenario: Нет rescue вне managed
- **WHEN** все login-способные учётки — managed роль-учётки с заблокированным паролем
- **THEN** doctor печатает Warn про потенциальный lockout, но код не валит

### Requirement: status read-only сводка

`census status` ДОЛЖЕН (MUST) только читать и печатать: managed-учётки с их `from_version`,
персист-версию декларации, и (если декларация задана) сводку drift. `status` ДОЛЖЕН (MUST)
всегда завершаться нулевым кодом.

#### Scenario: Сводка состояния
- **WHEN** оператор запускает status
- **THEN** печатаются managed-учётки, версии и drift-сводка, код 0

### Requirement: doctor integrity-проверки framework-слоя

`census doctor` ДОЛЖЕН (MUST) проверять целостность framework-слоя и сообщать находки как
предупреждения (Warn, без ненулевого кода — слой advisory): осиротевший маппинг (permission-id
вне каталога), `provides` без соответствующих поставленных файлов, незнакомый `dimension`,
коллизия `framework.id`. Gap-покрытие НЕ ДОЛЖНО (MUST NOT) вычисляться в `doctor` — оно остаётся
в `census framework coverage`, чтобы doctor не разбухал. Отсутствие дерева `frameworks/` НЕ
ДОЛЖНО (MUST NOT) давать находку.

#### Scenario: Осиротевший маппинг при doctor
- **WHEN** framework-маппинг ссылается на отсутствующее в каталоге разрешение
- **THEN** doctor печатает Warn, код не валит

#### Scenario: Нет дерева фреймворков
- **WHEN** каталог `frameworks/` отсутствует
- **THEN** doctor не выдаёт находок framework-слоя

#### Scenario: Коллизия id фреймворка при doctor
- **WHEN** два каталога объявляют один `framework.id`
- **THEN** doctor печатает Warn о коллизии целостности

