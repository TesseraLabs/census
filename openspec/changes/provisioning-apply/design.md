# Design: provisioning-apply

## Контекст

Срез 1 даёт `Plan { actions: Vec<Action> }` (Create/Update/Delete) из
`plan::diff(targets, state)`. Этот change добавляет исполнение плана. Вход apply:
декларация + role-store (как в plan) + текущий managed-реестр. Выход: ОС приведена к плану,
реестр обновлён, либо (при сбое) состояние откачено к моменту до apply.

`census apply` запускается **от root** (пишет в passwd/shadow/group/sudoers.d). Это повышает
планку безопасности: строгий парсинг входа, минимум доверия к декларации, никаких inject-
поверхностей (урок PwnKit/pkexec — root-процесс не должен доверять окружению/аргументам).

## Поток apply

```
census apply --declaration D [--managed M] [--trust-fs]
  1. verify trust(D)            // подпись+anti-rollback ИЛИ --trust-fs; иначе ОТКАЗ (fail-closed)
  2. parse D + read role-store  // как в plan (срез 1)
  3. resolve targets           // ResolvedAccount[]
  4. load managed state (M)
  5. plan = diff(targets, state)
  6. anti-lockout gate(plan)    // отказ, если план сносит последний путь входа
  7. backup auth-DB + touched sudoers.d   // full-file snapshot
  8. apply phases (create→update→delete), shadow-utils
       on phase error → restore from snapshot → ОТКАЗ (ненулевой код)
  9. write managed registry (atomic, last)
  10. drop/retain snapshot per policy
```

## Решения

### Р1. Мутация — shadow-utils (не прямая правка файлов)

`useradd`/`usermod`/`groupadd`/`gpasswd`/`userdel` (+ `chfn`, `passwd -l`). Census **не**
редактирует passwd/shadow/group напрямую.

Почему: парсинг/запись shadow security-чувствительны (блокировки `lckpwdf`, gshadow,
форматные крайние случаи); shadow-utils — каноничный путь ОС, уважает `/etc/login.defs` и
PAM-хуки. Переписывать это в Census — реимплементация с риском дыр. Минусы приняты: парсинг
кода возврата утилит (не stdout), GECOS-квирк Astra (`useradd -c` отвергает `:`/`=` →
маркер ставим `chfn` в безопасном формате), атомарность не на уровне утилиты — её даёт Р2.

Конкретика вызовов:
- **create**: `useradd -u <uid> -m -d <home> -s <shell> -N <role>` (без -c из-за квирка;
  GECOS-маркер — отдельным `chfn` после), затем `passwd -l <role>` (блок пароля),
  группы — `gpasswd`/`usermod -G`. authorized_keys НЕ создаём.
- **update**: shell — `usermod -s`; группы — `usermod -G <полный набор роли>` (абсолютная
  set-семантика). **Census владеет ПОЛНЫМ списком доп-групп managed роль-учётки**: роль-
  учётка — не человеческая, легитимных out-of-band групп у неё нет, поэтому абсолютная
  замена корректна и проще, чем gpasswd-дельты. (Инвариант: не назначать managed роль-
  учётке группы вне Census.) uid — отказ (uid стабилен §10; смена uid = деструктив, не в
  области идемпотентного update — диагностика).
- **delete**: `userdel -r <role>` (после anti-lockout-гейта; живые сессии — вне scope,
  отдельный change).

### Р2. Атомарность — full-file backup

Перед фазой apply Census снимает снапшот auth-баз целиком: `/etc/passwd`, `/etc/shadow`,
`/etc/group`, `/etc/gshadow` + каждый затрагиваемый `/etc/sudoers.d/census-*`. Снапшот —
в `/var/lib/census/rollback/<timestamp>/` (0700 root). При ошибке любой фазы — восстановление
файлов из снапшота (atomic rename обратно) и ненулевой выход.

Почему full-file, не per-object журнал: auth-базы крохотные (копия — микросекунды), снапшот
целиком даёт гарантированно консистентное прежнее состояние без разбора частичных мутаций
shadow-utils. Проще и пуленепробиваемее. (Спека §6 говорила per-object журнал — этот change
её уточняет на full-file; обновить core-spec §6.)

Граница: shadow-utils могут оставить артефакты (home-каталог при упавшем create). Восстановление
auth-баз снимает запись об учётке; осиротевший home чистится best-effort на откате (rm -rf
по home из плана) — не критично для auth.

### Р3. Маркер managed — root-only реестр

Авторитет — `/var/lib/census/managed.toml` (0600 root): список managed-объектов (учётки,
группы, sudoers-файлы) + `from_version`. Census трогает/удаляет объект ТОЛЬКО если он в
реестре. GECOS-маркер (`census-role-<role>`, без `:`/`=`) — вторичный человекочитаемый
признак, НЕ авторитет. Реестр пишется атомарно (temp+rename) **последним**, после успеха фаз.

Инвариант: объект с GECOS-меткой, но без записи в реестре → НЕ трогается (возможно чужой);
rescue запрещено заносить в реестр (см. Р4).

### Р4. Anti-lockout

«Последний путь входа» = Tessera-independent rescue (emergency-аккаунт и/или sshd
`UsePAM=no`), определённый ВНЕ Census. Census его структурно не трогает: rescue не в managed-
реестре → вне области by design (не эвристика). `apply` дополнительно гейтит: отказывается,
если план оставит 0 рабочих путей входа после применения (проверка: остаётся ≥1 путь —
rescue вне managed ИЛИ хотя бы одна непадающая роль-учётка с рабочим cert-входом). На этом
этапе проверка консервативна: достаточно подтвердить, что rescue-канал (вне managed)
присутствует; если rescue не сконфигурирован — apply требует `--i-understand-no-rescue`
(осознанный риск, логируется), чтобы не тихо запереть устройство.

### Р5. Недостижимость при создании (контракт §8)

Каждая создаваемая роль-учётка немедленно получает: заблокированный пароль (`passwd -l`,
shadow `!`), реальный shell (вход гейтит не shell, а отсутствие учётных данных + cert-путь
Tessera), отсутствие `~/.ssh/authorized_keys`. Это материализует модель (B), проверенную на
Astra 1.8.4 (срез §17). apply НЕ настраивает PAM-стек (зона Tessera Login) и НЕ назначает
parsec-метку (зона коммерческого ParsecBackend).

### Р6. sudoers.d

Если роль несёт sudo-право, Census кладёт `/etc/sudoers.d/census-<role>` через temp +
`visudo -c -f <temp>` (валидация) + atomic rename. Битый sudoers не активируется никогда.
Census владеет только `census-*`-файлами; чужие sudoers не трогает. Содержимое правила —
по соглашению role-store (право на заранее настроенную группу/alias); конкретный формат
правила фиксируется в spec-дельте.

### Р7. Доверие к декларации (fail-closed)

apply мутирует, только если декларация доверена:
- **managed**: валидная подпись + anti-rollback (version ≥ последнего применённого) — механизм
  подписи в отдельном change `declaration-trust`; здесь — точка вызова `verify_trust()` с
  заглушкой, возвращающей «не доверено» без `--trust-fs`.
- **standalone**: флаг `--trust-fs` — доверие целостности ФС/образа (root-only `/etc/census/`),
  осознанное решение оператора, логируется.
Любой иной случай → отказ ДО backup/мутаций.

## Безопасность (threat-анализ change'а)

Census apply — новый **root-провижинер**, новый актив в модели угроз. Угрозы и меры:

- **Подлог/откат декларации** (противник подсовывает декларацию, создающую привилегированную
  учётку или сносящую rescue): меры — Р7 (подпись+anti-rollback / --trust-fs fail-closed),
  Р4 (anti-lockout не даёт снести rescue), строгий парсинг (срез 1: deny_unknown_fields,
  валидация role-id закрыла `../foo` traversal, uid в диапазоне).
- **Lockout** (apply закрывает вход): Р4 gate + Р2 откат при сбое.
- **Порча sudoers** (битый файл → потеря sudo или дыра): Р6 `visudo -c` + atomic rename.
- **Подмена маркера managed** (root-инструмент ставит GECOS-метку, чтобы Census удалил чужую
  учётку): Р3 — авторитет реестр, не GECOS; объект без записи в реестре не трогается.
- **TOCTOU/гонки** при мутации auth-баз: shadow-utils берут `lckpwdf`; Census не пишет файлы
  параллельно с утилитами; реестр — atomic rename.
- **Привилегия процесса** (root, урок PwnKit): не доверять окружению/аргументам, строгий вход,
  явные пути, без shell-инъекций (вызовы утилит — argv-массивом, не строкой shell).
- **Осиротевший rollback-снапшот** (содержит копию shadow): каталог 0700 root, чистится по
  политике; не мировой доступ.

Дельта в workspace `threat-model.md` (§Census) — отдельным doc-проходом (трекается в
`census-product-design.md` §9). Здесь анализ зафиксирован для дизайна change'а.

## Тестирование

- **Unit** (Rust, без root): построение argv для каждой утилиты по `Action`; формирование
  GECOS-маркера (без `:`/`=`); сериализация реестра; anti-lockout-логика на фейковом наборе
  путей; verify_trust (отказ без --trust-fs).
- **Контейнер/VM** (root): реальная материализация — create→учётка с `!`-паролем, реальным
  shell, без authorized_keys; update групп; sudoers.d через `visudo -c`; userdel; откат при
  инъецированном сбое фазы (восстановление passwd/shadow из снапшота); недостижимость
  (попытка su non-root/ssh/пароль → отказ, как в прототипе §17).
- **Anti-lockout**: план, сносящий последний путь → отказ apply; rescue вне managed не тронут.
- **Идемпотентность**: повторный apply того же → 0 мутаций (план пуст).
- **Регресс**: apply не трогает не-managed объекты.

## Открытые вопросы

- Формат правила sudoers.d на роль (группа vs Cmnd_Alias) — зафиксировать в spec-дельте при
  реализации (зависит от соглашения role-store payload `sudo_role`/`groups`).
- Политика хранения rollback-снапшотов (хранить N последних? удалять после успеха?) — дефолт
  «удалять после успеха, хранить при сбое», уточнить.
- core-spec §6 «per-object журнал» → обновить на full-file backup (Р2) при синхронизации канона.
