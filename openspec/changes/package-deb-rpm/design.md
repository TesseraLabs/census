## Context

Релиз census (`release.yml`, триггер `v*`-тег) сейчас собирает `static-pie`,
стрипнутый, musl-слинкованный бинарь и публикует его на GitHub Release с `.sha256`.
Бинарь не зависит от версии libc — ставится на старый glibc (Astra SE 1.8).

Бинарь захардкоживает свои рантайм-пути (проверено в коде):
- бинарь: `/usr/bin/census`;
- каталог permissions: `/usr/share/census/permissions` (+ override
  `/etc/census/permissions.d`) — `src/cli/mod.rs::default_catalog_roots`;
- frameworks: `/usr/share/census/frameworks` (+ override
  `/etc/census/frameworks.d`) — `src/framework.rs`;
- l10n живёт **внутри** дерева permissions
  (`/usr/share/census/permissions/l10n/...`) — `src/l10n.rs`;
- дефолт декларации: `/etc/census/declaration.toml` (операторский, не шипается).

Раскладка пакета обязана точь-в-точь совпасть с этими путями — иначе
установленный census найдёт пустой каталог.

## Goals / Non-Goals

**Goals:**
- Публиковать `.deb` и `.rpm` рядом с musl-бинарём на том же `v*`-теге.
- Один декларативный источник правды для обоих форматов.
- Пакеты без рантайм-зависимостей; ставятся на старый glibc.
- Раскладка строго по FHS-путям, которые ждёт бинарь.

**Non-Goals:**
- systemd-unit (census — on-demand CLI, не демон).
- Maintainer-скрипты (postinst/postrm/preinst).
- Шипать `/etc/census/declaration.toml` (политика оператора).
- arm64 / мульти-арх.
- Сборка пакетов на PR (smoke-валидация nfpm-конфига отклонена).
- Хостинг apt/yum-репозитория (ассеты — только загрузки Release).

## Decisions

**1. Инструмент: nfpm.** Один `packaging/nfpm.yaml` эмитит и `.deb`, и `.rpm` из
одного списка файлов. Ставится как один pinned-бинарь (по образцу `taplo` в
`ci.yml`) — без `rpmbuild`-chroot и `dpkg-dev` в CI.
_Альтернатива:_ `cargo-deb` + `cargo-generate-rpm` — два инструмента, два конфига,
большие деревья данных (`share/permissions/**`, `share/frameworks/**`) надо
перечислять как assets дважды. nfpm даёт единый источник правды.

**2. Переиспользование бинаря, без нового job.** Шаги пакетирования добавляются в
существующий `build`-job после шага `Package`: musl-бинарь собирается и стрипается
ровно один раз и переиспользуется. Никакого нового триггера — только `v*`-тег.
_Альтернатива:_ отдельный `package`-job — лишний musl-билд или передача артефакта
между job'ами; не оправдано для одного бинаря.

**3. Версия из тега.** `VERSION=${GITHUB_REF_NAME#v}` пробрасывается в nfpm через
env и интерполируется в `nfpm.yaml`. Существующий гард «тег == `Cargo.toml`
version» в `release.yml` уже гарантирует отсутствие рассинхрона.

**4. Нет Depends.** Бинарь статический musl → пакеты без объявленных
рантайм-зависимостей; ставятся на любой целевой дистрибутив без подбора libc.

**5. Пустые override-директории.** `/etc/census/{permissions.d,frameworks.d}/`
шипаются пустыми (`type: dir` в nfpm). Бинарь и так трактует их отсутствие как
«нет оверрайдов», так что это неповеденческое удобство — оператор сразу видит
место для drop-in'ов.

**6. Раскладка файлов (FHS):**

| Источник | Назначение | Режим |
|---|---|---|
| `census` (musl, стрипнут) | `/usr/bin/census` | 0755 |
| `share/permissions/**` | `/usr/share/census/permissions/` | 0644 |
| `share/frameworks/**` | `/usr/share/census/frameworks/` | 0644 |
| `examples/**` | `/usr/share/doc/census/examples/` | 0644 |
| `README.md`,`CHANGELOG.md`,`LICENSE` | `/usr/share/doc/census/` | 0644 |
| _(пусто)_ | `/etc/census/permissions.d/` | 0755 |
| _(пусто)_ | `/etc/census/frameworks.d/` | 0755 |

**7. Метаданные:** name `census`; arch `amd64`(deb)/`x86_64`(rpm); section/group
`admin`; vendor `TesseraLabs`; license `AGPL-3.0-only`; homepage
`https://github.com/TesseraLabs/census`; maintainer — релизная идентичность
TesseraLabs.

## Risks / Trade-offs

- **Дрейф путей: раскладка пакета расходится с захардкоженными константами бинаря**
  → таблица раскладки выверена против `default_catalog_roots`, корней
  `framework.rs` и l10n-дерева; смена констант в коде требует синхронной правки
  `nfpm.yaml` (зафиксировано в этом design как контракт).
- **Поломка nfpm-конфига ловится поздно (на теге, не на PR)** → сборка пакетов —
  отдельный шаг, падающий до публикации (Release не выходит с битым ассетом);
  per-PR smoke осознанно отклонён ради чистоты CI.
- **Пин версии nfpm устаревает** → версия и URL фиксированы в workflow (как
  `taplo`); обновление — явная правка, не плавающий `latest`.
- **rpm на хосте с принудительным non-empty `Requires`-policy** → census ставится
  как обычный пользовательский пакет; статический бинарь зависимостей не требует,
  кейс не применим к целевым дистрибутивам.

## Migration Plan

- Деплой: добавить `packaging/nfpm.yaml` и шаги в `release.yml`; следующий
  `v*`-тег публикует пакеты автоматически.
- Откат: удалить добавленные шаги/список ассетов — релиз возвращается к публикации
  только musl-бинаря; новых обязательных зависимостей пайплайна не вводится.
- Разовая приёмка (рекоменд., в release-runbook, не автоматизируется здесь): на
  Debian/Astra `dpkg -i census_*.deb`, затем `census --help` и `census plan` по
  примеру декларации разрешают каталог из `/usr/share/census/permissions` без
  доп. флагов; то же `rpm -i` на RHEL-семействе.

## Open Questions

- Нет. Точное строковое значение maintainer берётся из релизной идентичности
  TesseraLabs на этапе реализации.
