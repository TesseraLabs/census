# Tasks: provisioning-doctor

## 1. SystemInspector (шов чтения ОС)

- [x] 1.1 `inspect.rs`: trait `SystemInspector` (account/password_locked/has_authorized_keys/
  census_marked_accounts/login_capable_non_managed) + `AccountFacts`
- [x] 1.2 `LiveInspector` — getent passwd/shadow/group, `~/.ssh/authorized_keys`, GECOS-метка
- [x] 1.3 `FakeInspector` (тесты) — задаваемые факты

## 2. Проверки doctor

- [x] 2.1 `doctor.rs`: `Finding { severity, check, target, message }`, `Severity{Error,Warn}`,
  `DoctorReport { findings }` + `has_errors()`
- [x] 2.2 §4 целостность реестра: запись без учётки / GECOS-метка без записи / дрейф
  uid-shell-групп → Error
- [x] 2.3 §8 недостижимость: пароль не заблокирован / есть authorized_keys / нет учётки → Error
- [x] 2.4 §7 anti-lockout: нет login-способной учётки вне managed → Warn
- [x] 2.5 drift (если декларация): plan непуст → Warn (через существующий plan-движок)
- [x] 2.6 Unit (FakeInspector): каждая проверка позитив/негатив; has_errors

## 3. status

- [x] 3.1 `status.rs` (или в doctor.rs): managed-учётки+from_version, персист-версия, drift-сводка
- [x] 3.2 Unit: вывод; всегда без ошибок

## 4. CLI + коды возврата

- [x] 4.1 `census doctor [--declaration P] [--managed M]` → ненулевой при has_errors, иначе 0
- [x] 4.2 `census status [--declaration P] [--managed M]` → всегда 0
- [x] 4.3 main.rs подкоманды; рендер findings человекочитаемо
- [x] 4.4 Unit (cli): код возврата doctor (Error→ненулевой, чисто→0); status→0

## 5. Контейнер-интеграция (дополнить harness)

- [x] 5.1 После apply: `doctor` чисто (код 0); `status` печатает managed+version
- [x] 5.2 Деградация: unlock пароль роль-учётки → doctor Error (ненулевой)
- [x] 5.3 Деградация: положить authorized_keys → doctor Error
- [x] 5.4 Спуфинг: GECOS-метка census на чужой учётке вне реестра → doctor Error

## 6. Канон + ревью

- [x] 6.1 core-spec §14: doctor/status реализованы (что проверяет, advisory PAM-ограничение)
- [x] 6.2 master-code-reviewer перед коммитом
