# Proposal: provisioning-apply

## Why

Срез 1 Census (declaration + role-store reader + plan-diff + `census plan`) даёт **план**
изменений (create/update/delete роль-учёток), но ничего не **применяет** — это read-only.
Чтобы Census выполнял свою функцию (привести Unix-объекты доступа устройства в соответствие
декларации), нужен `census apply`: материализация плана в passwd/shadow/group/sudoers.d/
systemd-лимиты.

Это самый рисковый срез: он первым **пишет в auth-критичные базы ОС**. Ошибка способна
закрыть вход на устройство (lockout) или испортить sudoers (потеря привилегий или дыра).
Поэтому apply должен быть атомарным (откат при сбое), anti-lockout (не сносит последний путь
входа), fail-closed (невалидная декларация → отказ до мутаций) и материализовать инвариант
недостижимости роль-учётки (заблокированный пароль, нет ключей) при создании.

Канон: `tessera-ws/specs/2026-06-18-census-core-spec.md` §5–§10. Решения дизайн-сессии
2026-06-19: мутация через **shadow-utils** (не переписываем парсинг shadow), атомарность —
**full-file backup** auth-баз перед apply.

## What Changes

- Новая capability **provisioning-apply**: `census apply` — применяет план среза 1.
- **Мутация через shadow-utils**: `useradd`/`usermod`/`groupadd`/`gpasswd`/`userdel`;
  Census не редактирует passwd/shadow напрямую (security-чувствительный парсинг — зона ОС).
- **Атомарность full-file backup**: перед apply — снапшот passwd/shadow/group/gshadow и
  затрагиваемых sudoers.d-файлов; при сбое любой фазы — восстановление из снапшота.
- **Недостижимость при создании** (контракт §8): новая роль-учётка создаётся с реальным
  shell, затем пароль блокируется (`passwd -l`), authorized_keys не создаётся; GECOS-маркер
  ставится `chfn` в безопасном формате (без `:`/`=` — Astra-квирк).
- **Маркер managed**: root-only реестр `/var/lib/census/managed.toml` — авторитет; Census
  трогает/удаляет объект, только если он в реестре; реестр обновляется атомарно последним.
- **Anti-lockout gate**: apply отказывается выполнять план, если он сносит последний путь
  входа; rescue/break-glass структурно вне managed (не эвристика).
- **sudoers.d на роль**: запись через temp + `visudo -c` + atomic rename (битый sudoers не
  активируется); Census владеет только `census-<role>`-файлами.
- **Доверие к декларации (fail-closed)**: apply применяет план, только если декларация
  доверена — подписана и прошла anti-rollback, ЛИБО явный `--trust-fs` (standalone, доверие
  целостности ФС, логируется). Невалидно → отказ до любых мутаций.

## Non-goals (отдельные change'и)

- Формат подписи деклараций и anti-rollback-state (capability `declaration-trust`) — здесь
  apply поддерживает `--trust-fs`; полная подпись — следующий change.
- Reconcile при живой сессии (§12): координация с Tessera session-registry — здесь `delete`
  гейтится anti-lockout, но живые сессии не учитываются (отдельный change `live-reconcile`).
- `census doctor` (проверки недостижимости §8) и `census status` — отдельный change.
- Подхват (watch/timer §11) — здесь только разовый `census apply`.
- Доставка деклараций через Control, drift по парку (census-enterprise).
