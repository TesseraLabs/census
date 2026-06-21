# declaration-trust Specification

## Purpose
TBD - created by archiving change declaration-trust. Update Purpose after archive.
## Requirements
### Requirement: Верификация подписи декларации (managed)

В managed-режиме (без `--trust-fs`) `census apply` ДОЛЖЕН (MUST) верифицировать подпись
Ed25519 декларации по пинённому публичному ключу (`/etc/census/trust.pub`) ДО любых мутаций
и до снятия снапшота. Подпись ДОЛЖНА (MUST) покрывать байты декларации с полностью удалённой
строкой `signature` (строка, чей первый непробельный токен — `signature`, за ним `=`),
включая её перевод строки. При невалидной/отсутствующей подписи, отсутствии или нечитаемости
trust-anchor `census apply` ДОЛЖЕН (MUST) отказывать (fail-closed), не выполняя мутаций.

#### Scenario: Валидно подписанная декларация
- **WHEN** apply запущен без `--trust-fs` с декларацией, подписанной ключом trust-anchor
- **THEN** подпись проходит, apply продолжается

#### Scenario: Подделанная или неподписанная декларация
- **WHEN** apply запущен без `--trust-fs`, подпись отсутствует или не сходится с trust-anchor
- **THEN** apply отказывает до любых мутаций и до снапшота (fail-closed)

#### Scenario: Отсутствует trust-anchor
- **WHEN** apply запущен в managed-режиме, а `/etc/census/trust.pub` отсутствует или нечитаем
- **THEN** apply отказывает (fail-closed)

### Requirement: Anti-rollback по монотонной версии

`census apply` ДОЛЖЕН (MUST) отвергать декларацию, чей `version` меньше последнего успешно
применённого, который Census персистит в root-only `/var/lib/census/declaration.version`.
Декларация с `version`, равным персисту, ДОЛЖНА (MUST) допускаться (идемпотентный повтор —
план будет пуст). Персист последнего применённого `version` ДОЛЖЕН (MUST) обновляться только
после успешного apply, чтобы откат при сбое фазы не двигал anti-rollback-счётчик.

#### Scenario: Реплей старой декларации
- **WHEN** apply получает валидно подписанную декларацию с `version` меньше персиста
- **THEN** apply отвергает её (anti-rollback), мутаций нет

#### Scenario: Повтор той же версии
- **WHEN** apply получает декларацию с `version`, равным персисту
- **THEN** apply допускается и является no-op (план пуст)

#### Scenario: Персист двигается только после успеха
- **WHEN** apply новой версии падает на фазе и откатывается
- **THEN** персист версии не изменяется (следующий apply той же версии не считается откатом)

### Requirement: Trust-anchor pinning

Публичный ключ для верификации ДОЛЖЕН (MUST) браться только из пинённого root-only файла
`/etc/census/trust.pub`; произвольный ключ из недоверенного источника НЕ ДОЛЖЕН (MUST NOT)
приниматься. Поле `signature` в декларации ДОЛЖНО (MUST) корректно парситься строгим
парсером декларации (не вызывать ошибку unknown-field). Алгоритм подписи ДОЛЖЕН (MUST) быть
заменяемым (Ed25519 сейчас; ГОСТ — будущее расширение через ту же точку верификации).

#### Scenario: Декларация со строкой signature
- **WHEN** декларация содержит строку `signature = "<hex>"`
- **THEN** строгий парсер принимает её, верификация использует пинённый trust-anchor

### Requirement: Standalone-доверие как альтернатива

`census apply` с явным `--trust-fs` ДОЛЖЕН (MUST) пропускать проверку подписи и anti-rollback,
доверяя целостности ФС (root-only `/etc/census/`), и логировать это решение. Без `--trust-fs`
и без валидной подписи apply ДОЛЖЕН (MUST) отказывать (ровно один из двух режимов доверия
обязателен — fail-closed).

#### Scenario: Standalone-режим
- **WHEN** apply запущен с `--trust-fs`
- **THEN** подпись и anti-rollback не проверяются, решение о доверии ФС логируется, apply продолжается

