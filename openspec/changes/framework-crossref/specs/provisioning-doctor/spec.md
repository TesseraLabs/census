## ADDED Requirements

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
