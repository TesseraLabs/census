# Tasks: provisioning-apply

## 1. Доверие и предусловия

- [ ] 1.1 `trust.rs`: `verify_trust(decl, opts) -> Result<TrustDecision, _>` — заглушка подписи
  (managed → «не доверено» до change `declaration-trust`), `--trust-fs` → доверено+лог; иначе отказ
- [ ] 1.2 Unit: отказ без `--trust-fs` и без подписи (fail-closed); `--trust-fs` → Ok + лог-запись
- [ ] 1.3 CLI: подкоманда `apply` (clap) с `--declaration/--managed/--trust-fs/--i-understand-no-rescue`

## 2. Бэкап и откат (full-file)

- [ ] 2.1 `backup.rs`: снапшот passwd/shadow/group/gshadow + затрагиваемых `sudoers.d/census-*`
  в `/var/lib/census/rollback/<ts>/` (0700 root); `restore()` — atomic rename обратно
- [ ] 2.2 Unit (tempdir, фейковые пути): снапшот→мутация→restore возвращает байт-в-байт
- [ ] 2.3 Политика хранения: удалять снапшот при успехе, сохранять при сбое

## 3. Мутаторы shadow-utils

- [ ] 3.1 `mutate.rs`: построение argv для create/update/delete (useradd/usermod/gpasswd/userdel,
  chfn-маркер без `:`/`=`, `passwd -l`); вызов argv-массивом, проверка кода возврата
- [ ] 3.2 Unit: argv для каждого `Action` корректен; GECOS-маркер без запрещённых символов
- [ ] 3.3 Unit: смена UID managed-учётки → ошибка (не перезапись)
- [ ] 3.4 create НЕ создаёт authorized_keys; после create — `passwd -l`

## 4. sudoers.d

- [ ] 4.1 `sudoers.rs`: запись `census-<role>` через temp + `visudo -c` + atomic rename
- [ ] 4.2 Unit/контейнер: битый sudoers (visudo -c фейл) → не активируется, фаза падает

## 5. Anti-lockout

- [ ] 5.1 `lockout.rs`: gate — останется ли ≥1 путь входа после плана (rescue вне managed ИЛИ
  непадающая роль-учётка); rescue отсутствует + нет флага → отказ
- [ ] 5.2 Unit: план сносит последний путь → отказ; rescue вне managed не в области

## 6. Оркестратор apply

- [ ] 6.1 `apply.rs`: поток verify→parse→resolve→diff→lockout-gate→backup→phases→registry;
  на ошибке фазы — restore + ненулевой выход
- [ ] 6.2 Реестр managed: запись атомарно последней (temp+rename), `from_version`
- [ ] 6.3 CLI wiring `census apply` → `apply::run`
- [ ] 6.4 Идемпотентность: пустой план → ноль мутаций (unit)

## 7. Интеграция (root, контейнер/VM)

- [ ] 7.1 create→учётка с `!`-паролем, реальным shell, без authorized_keys
- [ ] 7.2 update групп; userdel; sudoers.d через visudo -c
- [ ] 7.3 откат при инъецированном сбое фазы (passwd/shadow восстановлены)
- [ ] 7.4 недостижимость: su(non-root)/ssh/пароль → отказ (повтор прототипа §17 на Astra VM)
- [ ] 7.5 регресс: apply не трогает не-managed объекты

## 8. Канон-синхронизация

- [ ] 8.1 core-spec §6: «per-object журнал» → full-file backup (Р2)
- [ ] 8.2 workspace `threat-model.md` §Census — дельта (отдельный doc-проход, трекается)
- [ ] 8.3 master-code-reviewer перед коммитом; коммит — в нерабочее окно
