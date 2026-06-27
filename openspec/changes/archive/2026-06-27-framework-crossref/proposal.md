## Why

Владельцу парка нужно доказать соответствие подсистемы доступа compliance-фреймворкам
(PCI-DSS — обязателен для банкоматов/card-data, CIS — де-факто baseline), но сегодня связь
«разрешение каталога ↔ требование фреймворка» он держит в голове или в Excel вручную. Census
уже материализует и трекает роль-учётки/группы/sudo-гранты — он в идеальной позиции дать
машиночитаемый cross-reference и ответить «какие access-требования фреймворка не покрыты ни
одной ролью». Делаем это расширяемо: CIS и PCI-DSS первыми, любой следующий фреймворк (ФСТЭК,
DISA STIG) добавляется данными, без правки кода.

## What Changes

- Новый **read-only слой cross-reference** поверх каталога разрешений: аннотирует
  «разрешение → control-id фреймворка» (many-to-many). Слой **advisory** — НЕ участвует в
  `compile`/grant/`apply`, ноль grant-мутации.
- Отдельное дерево данных `frameworks/<fw>/` с per-framework манифестом (`dimension` =
  `flat` | `os-layered`, `provides`), файлами маппинга `mappings/*.toml` (ключ = id разрешения,
  связь с полярностью `satisfies` / `risk` / `related`) и опциональным `controls.toml` (перечень
  контролей с флагом `owned` для gap-oracle).
- **Полярность связи**: маппинг различает «способность адресует контроль» (`satisfies`),
  «способность подрывает контроль» (`risk`), «нейтрально касается» (`related`). coverage считает
  покрытием только `satisfies`; новый `framework risk <fw>` перечисляет контроли под угрозой.
- **Generic-загрузчик**, фреймворк-агностичный: новый фреймворк = новое поддерево, код не
  трогается. `os-layered` переиспользует существующий резолвер цепочки слоёв каталога.
- CLI: `census show <role> --framework <fw|all>` (с полярностью), новая подкоманда `census
  framework list|coverage|show|risk`, флаг `--format json`.
- `census doctor` получает **integrity-проверки** framework-файлов (осиротевшие маппинги,
  `provides` без соответствующих файлов, незнакомый `dimension`, коллизия `framework.id`).
- Стартовые open-данные: `pci-dss` (flat, req 7 + owned-флагнутые 8/10), `cis-controls`
  (flat, Safeguard §6).
- Граница домена **явная**: hardening-контроли помечаются `owned=false` — Census их намеренно
  не покрывает (device-hardening вне продукта). НЕ применяет настройки, НЕ наполняет каталог
  из фреймворка, НЕ лезет в auth-путь.

## Capabilities

### New Capabilities
- `framework-crossref`: форматы (манифест / mapping / controls), generic-загрузчик и
  dimension-резолв, forward/reverse индекс, CLI (`show --framework`, подкоманда `framework`),
  lint, provenance, доверие (advisory, подпись пакета, штамп версии в выводе).

### Modified Capabilities
- `provisioning-doctor`: добавляет integrity-проверки framework-слоя (целостность манифестов
  и маппингов) как warning-класс; gap-покрытие остаётся в `census framework coverage`, не в doctor.

## Impact

- Новый код: модуль загрузчика framework-слоя (Rust, serde+toml), CLI-ветки `framework` и флаг
  `--framework` у `show`. Переиспользует резолвер os-цепочки из `permission-catalog`.
- Зависимость по порядку: `census show` вводится change'ем `permission-catalog` — интеграция
  `--framework` опирается на него.
- Данные: новое дерево `/usr/share/census/frameworks/` (vendor) + `/etc/census/frameworks.d/`
  (site-overlay); пакетная поставка подписанным `.deb` (как vendor-каталог).
- Threat-model: аддендум в `tessera-ws/specs/threat-model.md` §5.14 — framework-слой read-only,
  риск = искажение compliance-заявления (не эскалация), контроль = подпись пакета + штамп версии.
- Лиценз: заголовки контролей пишутся своими словами (номера = факты; текст требований
  PCI-DSS / CIS — копирайт, не воспроизводим).
- Вне scope change'а: compliance-отчёт по парку (Control / commercial), ФСТЭК-пакет, os-layered
  `cis-benchmark`-данные.
