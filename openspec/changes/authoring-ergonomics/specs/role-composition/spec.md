# role-composition Delta Specification

## ADDED Requirements

### Requirement: Инлайн sudo-команды в роли (payload.sudo)

Роль-payload ДОЛЖЕН (MUST) принимать необязательное `payload.sudo` — список строк
абсолютных путей команд — как raw escape-hatch примитив, парный каталожному `sudo = [...]`
и существующему `[[payload.files]]`. Значения ДОЛЖНЫ (MUST) быть **только литеральными**:
плейсхолдеры `{param}` НЕ ДОЛЖНЫ (MUST NOT) поддерживаться (параметризация с confinement —
прерогатива catalog-id с его `[params.X]`). Каждое значение ДОЛЖНО (MUST) валидироваться
до материализации — абсолютный путь, не пустой, без shell-метасимволов — и при невалиде
resolve ДОЛЖЕН (MUST) отказывать (fail-closed). Валидные команды ДОЛЖНЫ (MUST) юнионироваться
в sudo-команды учётки наравне с раскрытием каталога.

#### Scenario: Литеральная команда материализуется
- **WHEN** роль несёт `payload.sudo = ["/usr/sbin/myapp-reload"]`
- **THEN** команда попадает в sudo-команды учётки рядом с раскрытием каталога

#### Scenario: Не-абсолютный или метасимвольный путь отвергается
- **WHEN** `payload.sudo` содержит относительный путь, пустую строку или shell-метасимвол
- **THEN** resolve отказывает (fail-closed), материализации нет

#### Scenario: Union с каталожным sudo
- **WHEN** роль несёт и `permissions` с sudo-командами, и `payload.sudo`
- **THEN** итоговый набор sudo-команд — объединение обоих

### Requirement: Видимость raw-примитивов в обзоре роли

`census show` и `census compile --lint` ДОЛЖНЫ (MUST) помечать инлайн `payload.sudo` как
raw / unlabeled escalation-capable — этот примитив обходит risk-label каталога, и ревьюер
ДОЛЖЕН (MUST) видеть его как некурируемый (наравне с `[[payload.files]]`).

#### Scenario: Инлайн-sudo подсвечен в show
- **WHEN** роль с `payload.sudo` отображается `census show`
- **THEN** запись помечена как raw / unlabeled escalation-capable
