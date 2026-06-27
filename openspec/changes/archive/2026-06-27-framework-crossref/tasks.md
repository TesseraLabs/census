## 1. Форматы и парсинг

- [x] 1.1 Типы `FrameworkManifest` (`id`, `version`, `title`, `dimension`, `provides`) с serde+toml, строгий парсинг структуры
- [x] 1.2 Тип файла маппинга: `permission-id → controls: Vec<String>`, мёрж файлов по имени с union+dedup дублей
- [x] 1.3 Тип `controls.toml`: контроль с `title` + обязательным `owned: bool`; ошибка при отсутствии `owned`
- [x] 1.4 Толерантность к незнакомым permission-id и forward-compat для незнакомых `dimension`/`provides` (пропуск + warning)
- [x] 1.5 Юнит-тесты парсинга: валидные/битые манифесты, мёрж дублей, отсутствие `owned`

## 2. Generic-загрузчик и индексы

- [x] 2.1 Сканирование `frameworks/*/framework.toml` в vendor (`/usr/share`) и site-overlay (`/etc/census/frameworks.d`)
- [x] 2.2 Резолв `flat`: чтение `mappings/*.toml` напрямую
- [x] 2.3 Резолв `os-layered`: переиспользовать резолвер ос-цепочки каталога для `mappings/<os>/*.toml`
- [x] 2.4 Построение forward-индекса `permission-id → {framework → [control-id]}`
- [x] 2.5 Построение reverse-индекса `framework → control-id → [permission-id]` + загрузка `controls.toml`
- [x] 2.6 Provenance: фиксировать источник (фреймворк/слой/файл) каждого маппинга
- [x] 2.7 Инвариант read-only: загрузчик не вызывается из `compile`/`plan`/`apply`/реестра; тест отсутствия дерева `frameworks/`
- [x] 2.8 Юнит-тесты: flat и os-layered резолв, оба индекса, provenance, пустое дерево

## 3. CLI: show --framework

- [x] 3.1 Флаг `--framework <fw|all>` у `census show <role>`
- [x] 3.2 Вывод control-id + provenance рядом с каждым разрешением; явная пометка «нет маппинга»
- [x] 3.3 `--format json` для машиночитаемого вывода со штампом `id`+`version`
- [x] 3.4 Тесты: роль с маппингом, разрешение без маппинга, `all`, json-штамп версии

## 4. CLI: подкоманда framework

- [x] 4.1 `census framework list` — установленные фреймворки с `version` и `provides`
- [x] 4.2 `census framework show <fw>` — перечень контролей + статистика покрытия
- [x] 4.3 `census framework coverage <fw>` — gap-oracle: `owned=true` минус покрытые; вне-доменные помечены
- [x] 4.4 `--format json` для всех трёх; `--os-target` для os-layered coverage
- [x] 4.5 Тесты: list, coverage-расчёт, игнор `owned=false`, json

## 5. Lint и валидация

- [x] 5.1 Warning: осиротевший маппинг (permission-id вне каталога)
- [x] 5.2 Warning: рассинхрон `provides` ↔ поставленные файлы; ссылка на control-id вне `controls.toml`
- [x] 5.3 Warning: дельта членства `controls.toml` между версиями фреймворка
- [x] 5.4 Error: коллизия `framework.id` между каталогами
- [x] 5.5 Тесты на каждое правило lint

## 6. doctor integrity-проверки

- [x] 6.1 Включить integrity-находки framework-слоя в `census doctor` как Warn (без ненулевого кода)
- [x] 6.2 Не вычислять gap-покрытие в doctor; отсутствие дерева `frameworks/` → без находок
- [x] 6.3 Тесты: осиротевший маппинг → Warn, пустое дерево → нет находок, коллизия id → Warn

## 7. Стартовые open-данные

- [x] 7.1 Фреймворк `pci-dss` (flat): манифест 4.0, маппинги req 7 ядро + owned-флагнутые 8/10, `controls.toml`
- [x] 7.2 Фреймворк `cis-controls` (flat): манифест, маппинги Safeguard §6, `controls.toml`
- [x] 7.3 Заголовки контролей — своими словами (номера = факты; текст требований не копировать)
- [x] 7.4 Упаковка дерева `frameworks/` в vendor-пакет (как каталог разрешений)

## 8. Документация и threat-model

- [x] 8.1 Аддендум в `tessera-ws/specs/threat-model.md` §5.14: framework-слой read-only, риск = искажение compliance-заявления, контроль = подпись пакета + штамп версии
- [x] 8.2 README/доки: команды `show --framework`, `framework list/coverage/show`, формат дерева фреймворка
- [x] 8.3 Лиценз-нота в репо про заголовки контролей своими словами
- [x] 8.4 `openspec validate framework-crossref --strict` зелёный; ревью master-code-reviewer перед коммитом

## 9. Полярность связи (satisfies / risk / related) + framework risk

- [x] 9.1 Сменить `MappingEntry`: `controls` → три опц. списка `satisfies`/`risk`/`related` (default пусто, strict); мёрж по полярностям с dedup
- [x] 9.2 Forward/reverse индексы несут полярность; coverage считает покрытием ТОЛЬКО `satisfies`
- [x] 9.3 `show --framework` печатает полярность визуально (satisfies/risk/related) + json с полярностью каждой связи
- [x] 9.4 Команда `census framework risk <fw>` — контроли с `risk`-связью + угрожающие разрешения, независимо от `owned`; `--format json`
- [x] 9.5 Lint: осиротевший/неизвестный control-id охватывают все три полярности; один control-id в `satisfies` И `risk` одного разрешения → ошибка (противоречие)
- [x] 9.6 Мигрировать стартовые данные: `pci-dss`/`cis-controls` на `satisfies`; `log-admin→10.5.1` как `risk`; убрать мутные satisfies на owned=false
- [x] 9.7 Обновить/добавить тесты: полярность в парсинге/индексах/coverage/show/risk/lint; обновить README (`framework risk`, формат полярности)
- [x] 9.8 `cargo build`/`test`/`clippy` зелёные; `openspec validate --strict`; ревью master-code-reviewer
