# catalog-resolution Delta Specification

## ADDED Requirements

### Requirement: Управление каталожными корнями (additional / no-default)

Каждая раскрывающая каталог подкоманда ДОЛЖНА (MUST) предоставлять `--additional-catalog-dir`
(повторяемый) — дописывающий корни к встроенным дефолтам — и булев `--no-default-catalog-dirs`,
выкидывающий встроенные дефолты из списка. Это касается plan, apply, compile, show,
catalog coverage, catalog which-grants и framework lint. Без флагов используются дефолты
(`/usr/share/census/permissions`, `/etc/census/permissions.d`). При `--no-default-catalog-dirs`
без единого `--additional-catalog-dir` (ноль корней) команда ДОЛЖНА (MUST) отказывать с явной
ошибкой и ненулевым кодом возврата, НЕ раскрывая каталог в пустоту. Прецеденс «later wins»
(коллизия permission-id — побеждает корень позже по списку) ДОЛЖЕН (MUST) сохраняться внутри
итогового списка корней.

#### Scenario: Дефолты без флагов
- **WHEN** подкоманда вызвана без catalog-флагов
- **THEN** используются встроенные дефолтные корни

#### Scenario: Дополнительные корни поверх дефолтов
- **WHEN** задан один или несколько `--additional-catalog-dir`
- **THEN** они дописываются после дефолтных корней (later wins)

#### Scenario: Изоляция от дефолтов
- **WHEN** заданы `--no-default-catalog-dirs` и хотя бы один `--additional-catalog-dir`
- **THEN** дефолты исключены, используются только переданные корни

#### Scenario: Ноль корней — отказ
- **WHEN** задан `--no-default-catalog-dirs` без единого `--additional-catalog-dir`
- **THEN** команда отказывает с явной ошибкой и ненулевым кодом возврата

## REMOVED Requirements

### Requirement: Флаг --catalog-dir

`--catalog-dir` удаляется без алиаса (репа приватная, внешних потребителей нет). Его роль
(дописывание корней к дефолтам) переходит к `--additional-catalog-dir`.

#### Scenario: Старый флаг отсутствует
- **WHEN** подкоманда вызвана с `--catalog-dir`
- **THEN** clap отвергает неизвестный аргумент (флаг удалён)
