## Context

Census провижинит доступ вперёд: file-access гранты, группы, sudoers, лимиты. Но не отвечает на
обратный вопрос — что роль-учётка фактически достижима читает/пишет в системе сверх least-privilege
замысла. Ambient over-permission (world-writable `/var/spool/cron`, world-readable секрет) подрывает
ограниченного юзера незаметно для оператора. Существующие куски, на которые опираемся: `doctor`
(read-only, exit-code, finding-модель), `fileaccess.rs::AclBackend` (нативное чтение POSIX ACL),
`coverage.rs` (классификатор security-relevant путей, сужение `config`-знаменателя).

Ограничения: Census — один Rust-крейт (serde+toml, clap, thiserror); работа под root; fail-safe;
CLI-контракт залочен golden-тестами (schemars/clap). Слой обязан быть строго read-only, как doctor.

## Goals / Non-Goals

**Goals:**

- Точная экспозиция под принципал: что он достижимо читает/пишет, с rigorous reachability (POSIX
  access + ACL + обязательная x-траверсия предков) — без ложняков «777 за закрытым каталогом».
- Глобальная posture-карта опасных классов прав (world-writable, setuid/setgid, world-readable
  секреты, broad-group-writable).
- Честная классификация находки: риск (escalation/leak/tamper), severity, и путь ремедиации
  (ambient руками vs in-model правкой декларации).
- Killer-фильтр: для managed-учётки показывать только ЛИШНИЙ доступ сверх выданного каталогом.

**Non-Goals:**

- Никаких мутаций (chmod/setfacl) — read-only.
- Генерация TOML-патча ремедиации (finding только классифицирует; патч — отдельный change).
- NSS/LDAP-резолв принципала (v1 — локальные passwd/group).
- MAC-слой (SELinux/AppArmor/PARSEC) в reachability — вердикт DAC-only верхняя граница.
- Runtime/сессии; персист снапшота индекса между прогонами (v1 — индекс в памяти).

## Decisions

**Подход «скан-один-раз → permission-индекс → срезы» (vs пер-принципал обход / shell-out в find).**
Один обход охваченных корней строит индекс `{path, owner, group, mode, ACL, object-class}`,
переиспользуемый всеми запросами прогона. Альтернативы отвергнуты: пер-принципал обход
пере-сканирует ФС на каждую учётку (дорого для «expose все managed-роли»), а shell-out в `find`/
`getfacl` не умеет ответить «может ли uid N с группами {…} писать сюда» и хрупок в парсинге. Один
движок обслуживает оба режима: `audit fs` — срез индекса по опасным классам, `audit expose` — срез
access-eval под принципал.

**Rigorous reachability с x-траверсией предков.** Объект достижим только если каждый предок-каталог
даёт `x` принципалу. Это ключевое отличие от наивного `find -perm`: файл 777 за каталогом 700-owned-
root недостижим и не должен давать находку. Траверсия мемоизируется по дереву каталогов (каждый
каталог проверяется на `x` один раз на принципал). Access-check — стандартный POSIX: uid 0
short-circuit; owner→owner-class; ACL named-user→его запись&mask; gid∈gids или ACL named-group→
group-class&mask; иначе other. ACL-чтение переиспользует `AclBackend`.

**Killer-фильтр intended baseline.** Для Census-managed роль-учётки вычитаем home + пути, выданные
каталогом разрешений → показываем только лишний доступ сверх замысла (это и есть уникальная для
Census ценность). Для произвольного uid baseline нет → сырой reachability. Managed-статус берётся из
реестра `/var/lib/census/managed.toml`, выданные пути — из раскрытия её гранта.

**remediation_class честно делит ambient vs in-model.** Source доступа = чужой объект → `ambient`,
hint = ручной `chmod`/`setfacl`, без обещания авто-фикса (декларация чужой объект не тронет — спека
file-access это запрещает). Source = объект Census (своя группа/свой грант) → `in-model`, hint =
сузить декларацию. Это разрешает изначальное противоречие «декларацией не отобрать world-write».

**Переиспользование, не дублирование.** finding/severity/exit-code зеркалят `doctor.rs`; ACL-чтение
— `fileaccess.rs`; классификатор security-relevant путей и дефолтные корни — расширение `coverage.rs`;
CLI/JSON — golden-контракт (interface-contract, `UPDATE_CONTRACT=1`).

## Risks / Trade-offs

- [DAC-only вердикт может переоценить доступ — MAC (SELinux/PARSEC) реально ограничивает] →
  документируем вывод как верхнюю границу; пометка в каждом отчёте экспозиции.
- [Отчёт сам — чувствительный артефакт: карта слабых мест системы под root] → вывод НЕ включает
  содержимое секрет-файлов (только путь/режим/метаданные); это нормативное требование спеки.
- [Полный обход (`--full`) дорог и шумен на больших ФС] → дефолт = security-relevant корни; `--full`
  только по явному флагу; псевдо-ФС и сетевые монтирования всегда пропускаются.
- [Локальные passwd/group упускают NSS/LDAP-членство в группах → недооценка доступа] → advisory-
  ограничение задокументировано (как PAM-advisory у doctor); резолв через NSS — будущий change.
- [Большой индекс в памяти на огромных деревьях] → v1 ограничен охватом по умолчанию; персист/
  потоковая обработка — отложенная оптимизация, не входит в v1.

## Migration Plan

Аддитивный read-only слой: новая подкоманда `census audit` (`fs` / `expose`), новый модуль
`exposure/`, конфиг scan-roots/secret-globs/broad-groups. Существующие команды и спеки не меняются.
Откат тривиален — слой ничего не мутирует, удаление подкоманды безопасно. Golden-контракт CLI/JSON
фиксируется при первом включении (`UPDATE_CONTRACT=1`).

## Open Questions

- Порог severity для ненулевого exit-кода — фиксированный (high) или настраиваемый флагом? Дефолт —
  high; настраиваемость можно добавить позже.
- Точный дефолтный список security-relevant корней и broad-groups — финализировать при реализации,
  сверяясь с боевой Astra (как делали для config-знаменателя в coverage).
- Классификатор object-class (cron/systemd-unit/path-binary/sudoers/secret) — путь-эвристики vs
  явный конфиг-список глобов; склоняемся к конфиг-списку с дефолтами (тестируемо, расширяемо).
