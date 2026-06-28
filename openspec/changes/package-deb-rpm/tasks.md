## 1. Конфиг сборки пакетов

- [ ] 1.1 Создать `packaging/nfpm.yaml`: метаданные (name `census`, version из env
  `${VERSION}`, arch `amd64`/`x86_64`, section/group `admin`, vendor `TesseraLabs`,
  license `AGPL-3.0-only`, homepage репозитория, maintainer), пустой список
  Depends/Requires
- [ ] 1.2 В `packaging/nfpm.yaml` описать contents по таблице раскладки design:
  бинарь → `/usr/bin/census` (0755); `share/permissions/**` →
  `/usr/share/census/permissions/`; `share/frameworks/**` →
  `/usr/share/census/frameworks/`; `examples/**` →
  `/usr/share/doc/census/examples/`; `README.md`/`CHANGELOG.md`/`LICENSE` →
  `/usr/share/doc/census/`
- [ ] 1.3 В `packaging/nfpm.yaml` добавить пустые `type: dir`
  `/etc/census/permissions.d/` и `/etc/census/frameworks.d/` (0755)
- [ ] 1.4 Локально провалидировать конфиг: `VERSION=0.1.0 nfpm package -f
  packaging/nfpm.yaml -p deb -t /tmp` и `-p rpm`; убедиться что nfpm разрешает все
  пути-источники без ошибок

## 2. Интеграция в релизный пайплайн

- [ ] 2.1 В `release.yml` после шага `Package` добавить установку pinned-бинаря
  nfpm в `/usr/local/bin` (по образцу установки `taplo` в `ci.yml`: фиксированная
  версия и URL, без apt/компиляции)
- [ ] 2.2 Добавить шаг сборки пакетов: `VERSION=${GITHUB_REF_NAME#v} nfpm package
  -f packaging/nfpm.yaml -p deb -t .` и то же с `-p rpm -t .`
- [ ] 2.3 Добавить шаг контрольных сумм: `sha256sum` на каждый произведённый
  `census_*.deb` и `census-*.rpm` в одноимённый `.sha256`
- [ ] 2.4 Расширить `files:` в шаге `softprops/action-gh-release`: добавить `.deb`,
  `.rpm` и их `.sha256` к уже публикуемому musl-бинарю и его `.sha256`

## 3. Верификация раскладки против бинаря

- [ ] 3.1 Распаковать собранный `.deb` (`dpkg-deb -c` / `dpkg-deb -x`) и сверить,
  что пути файлов точно совпадают с константами бинаря: `/usr/bin/census`,
  `/usr/share/census/permissions` (с поддеревом `l10n/`),
  `/usr/share/census/frameworks`, пустые `/etc/census/{permissions.d,frameworks.d}`
- [ ] 3.2 Проверить метаданные: версия `.deb`/`.rpm` равна `[package] version` в
  `Cargo.toml`; список Depends/Requires пуст
- [ ] 3.3 Разовая приёмка на целевом хосте (release-runbook): `dpkg -i` на
  Debian/Astra, затем `census --help` и `census plan` по примеру декларации
  разрешают каталог из `/usr/share/census/permissions` без доп. флагов; то же
  `rpm -i` на RHEL-семействе

## 4. Финализация

- [ ] 4.1 Удалить superpowers-черновик
  `docs/superpowers/specs/2026-06-28-census-deb-rpm-packaging-design.md` (источник
  правды теперь openspec-change)
- [ ] 4.2 Прогнать `openspec validate package-deb-rpm`; ревью master-code-reviewer
  на диф `release.yml` + `nfpm.yaml`; PR в `main` (только off-hours, подписанный
  коммит)
