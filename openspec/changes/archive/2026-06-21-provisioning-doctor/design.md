# Design: provisioning-doctor

## Контекст

Диагностики read-only поверх того же входа, что `plan`: managed-реестр + role-store +
(опц.) декларация. Дополнительно — **живое чтение ОС** (shadow, authorized_keys, sudoers.d,
login-способные учётки), чего у `plan` нет (plan сверяет только с реестром). Ни одной мутации.

## Решения

### Р1. Шов чтения ОС — `SystemInspector`

Новый trait (по образцу `Provisioner`/`SystemState`), чтобы doctor тестировался без root/живой
системы:
```rust
pub trait SystemInspector {
    fn account(&self, name: &str) -> Option<AccountFacts>;     // uid, shell, groups, exists
    fn password_locked(&self, name: &str) -> Option<bool>;     // shadow поле начинается с !/* 
    fn has_authorized_keys(&self, name: &str, home: &Path) -> bool;
    fn census_marked_accounts(&self) -> Vec<String>;           // по GECOS-метке census-role-*
    fn login_capable_non_managed(&self, managed: &BTreeSet<String>) -> Vec<String>; // для §7
}
```
Реальный `LiveInspector` читает `getent passwd/shadow/group`, `~/.ssh/authorized_keys`,
GECOS. `FakeInspector` — для unit-тестов. doctor зависит от `&dyn SystemInspector`.

### Р2. Набор проверок

Каждая проверка → `Finding { severity, check, target, message }`. `Severity`:
- **Error** — нарушение инварианта безопасности; `doctor` → ненулевой код.
- **Warn** — заметка; код не валится (но печатается).

Проверки:
- **§4 целостность реестра** (Error):
  - запись реестра без живой учётки → Error (managed-объект пропал);
  - живая учётка с GECOS-меткой Census, но без записи в реестре → Error (чужая/поддельная —
    авторитет реестр, §4);
  - uid/shell/группы managed-учётки разошлись с реестром → Error (дрейф managed-объекта).
- **§8 недостижимость** (Error) — для каждой managed роль-учётки:
  - пароль НЕ заблокирован (shadow не `!`/`*`) → Error;
  - есть `~/.ssh/authorized_keys` → Error;
  - учётка отсутствует → Error (overlap с §4).
  - *Advisory*: полный анализ «ни один PAM-сервис не пускает помимо tessera» — НЕ делаем
    (разбор pam.d ненадёжен); вместо — проверяем конкретные учётные условия выше. Ограничение
    задокументировано.
- **§7 anti-lockout** (Warn): нет ни одной login-способной учётки вне managed (потенциальный
  lockout, если cert-путь сломан) → Warn.
- **drift** (Warn, только если задана декларация): `plan` непуст → Warn со сводкой.

### Р3. `status` (информ.)

Read-only вывод: managed-учётки + `from_version`; персист-версия (`declaration.version`);
если декларация задана — сводка drift (counts create/update/delete). Всегда код 0.

### Р4. Коды возврата

`doctor`: есть Error → ненулевой (для мониторинга/CI); только Warn / чисто → 0.
`status`: всегда 0.

## Безопасность

doctor — read-only, не расширяет поверхность. Ценность — **обнаружение**: спуфинг GECOS-маркера
(§4, ловится сверкой с реестром-авторитетом), деградация недостижимости (разблокированный
пароль/появившиеся ключи — напр. после ручного вмешательства), потенциальный lockout. doctor
в мониторинге = раннее предупреждение о сходе инварианта. Не мутирует (чинит `apply`).

## Тестирование

- **Unit** (`FakeInspector`): каждая Error/Warn-проверка — позитив и негатив; коды возврата
  (Error→ненулевой, чисто→0); status-вывод; drift через существующий plan-движок.
- **Контейнер** (дополнить harness): после `apply` — `doctor` чисто (код 0); затем ручная
  деградация (unlock пароль роль-учётки / положить authorized_keys / поставить GECOS-метку
  на чужую учётку) → `doctor` ловит и возвращает ненулевой; `status` печатает managed+version.

## Открытые вопросы

- Глубина §8-проверки PAM-стека — сейчас advisory (учётные условия). Если потребуется строгая
  гарантия «ни один сервис не пускает» — отдельный анализ pam.d (будущее).
- Формат вывода (человекочитаемый сейчас; `--json` для мониторинга — возможное расширение).
