# Документация Census

**Декларативная подготовка Unix-объектов доступа.** Census приводит слой доступа
устройства — роль-учётки, группы, `sudoers.d`, лимиты, файловые ACL — в
соответствие декларации. Идемпотентен, fail-safe, вне пути аутентификации.

Языки: [English](../en/index.md) · **Русский** · [中文](../zh/index.md)

## По ролям

### Оператор — развёртывание Census на устройстве

1. [getting-started.md](getting-started.md) — установка, настройка, первый
   `apply` и эксплуатация (плановый reconcile, проверки дрейфа, teardown). Начните
   отсюда.
2. [toml-reference.md](toml-reference.md) — полный формат TOML: каждое поле
   декларации и слайса роли, плюс режим предпросмотра `plan --diff`.
3. [audit.md](audit.md) — read-only **аудит экспозиции**: просканировать
   *фактические* права файловой системы устройства и найти, что субъект уже
   может достать сверх принципа наименьших привилегий (`census audit fs` /
   `census audit expose`).

### Автор каталога / пакетов — расширение каталога permissions

1. [`catalog-authoring.md`](../catalog-authoring.md) — авторинг permissions
   каталога и слоёв по ОС.
2. [`authoring-packages.md`](../authoring-packages.md) — авторинг add-on пакетов
   и курируемых тиров `<app>.{observe|operate|admin}`.

## Справка

- `../../README.md` — модель продукта, свойства безопасности, полный справочник
  CLI и граница open-core.
- `../../contract/*.schema.json` — авторитетные машиночитаемые схемы (декларация,
  role-store, permission каталога, framework, managed-реестр).
- `../../examples/` — полный запускаемый role-store + декларация.
