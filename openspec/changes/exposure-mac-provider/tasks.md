# Tasks: exposure-mac-provider

Open-ядро only (коммерческий бэкенд `census_mac_parsec` + census-enterprise overlay —
отдельный приватный трек, НЕ здесь). Реализация на Rust через `rust-pro`, срезами, TDD.
На каждый срез: `cargo test` + `cargo clippy --all-targets --all-features` зелёные, ревью
`master-code-reviewer`. Слой строго read-only. Открытый билд остаётся поведенчески идентичным
(NullMacProvider дефолт). Коммит/PR — вне рабочего окна (08:00–19:00 МСК).

## 1. SPI MacProvider + Null/Fake

- [x] 1.1 Модуль `src/exposure/mac.rs`: `enum MacSystem { Parsec, Selinux }` (serde/Display);
      непрозрачные `MacLabelId`/`MacContextId` (интернированные хэндлы, напр. newtype над u32/строкой).
- [x] 1.2 `trait MacProvider { system; object_label(path)->Option<MacLabelId>;
      principal_contexts(uid)->Vec<MacContextId>; permits(ctx,label,access)->bool;
      render_context(ctx)->String; render_label(label)->String; }`. Док: ядро не парсит метки, не
      предполагает порядок; `principal_contexts` — неупорядоченное множество.
- [x] 1.3 `NullMacProvider` (object_label→None, permits→true, system — н/д или отдельный признак
      «нет провайдера»). `FakeMacProvider` (настраиваемые метки/контексты/permit-таблица) для тестов.
- [x] 1.4 Unit: Null нейтрален (None/true); Fake отдаёт заданные метки/контексты; ядро гоняет
      непрозрачные id через permits/render не разбирая.

## 2. Композит DAC ∧ MAC в expose

- [x] 2.1 `effective()` НЕ трогать (остаётся чисто-DAC). Композит в `expose.rs` поверх: для finding
      при активном провайдере `ctxs = principal_contexts(uid).filter(|c| permits(c, object_label(path),
      access))`; пусто → suppress; иначе аннотация.
- [x] 2.2 `Finding`/`ExposureReport` получают поле `mac: Option<MacFinding>` где
      `MacFinding { system: MacSystem, reachable_in: Vec<String> }`; serde + JsonSchema; `None` при
      NullMacProvider/не-labeled.
- [x] 2.3 Инъекция провайдера в `exposure_report(...)` (доп. параметр `&dyn MacProvider`, дефолт Null
      на вызывающей стороне). Нота отчёта: активный провайдер → `DAC + <system>`, иначе `DAC_ONLY_NOTE`.
- [x] 2.4 Unit (FakeMacProvider): блок на всех контекстах → suppress; permit в Y, блок в X → finding с
      `reachable_in:[Y]`; NullMacProvider → вывод и нота идентичны текущим (снапшот-паритет).

## 3. Posture-режим (audit fs) аннотация

- [x] 3.1 В `fs_audit.rs` при активном провайдере — аннотировать объект `render_label(object_label)`;
      БЕЗ suppression (принципала нет). Поле `mac` находки несёт system + метку объекта (reachable_in
      пусто/н/п в posture — задокументировать форму).
- [x] 3.2 Unit: `audit fs` + FakeMacProvider на labeled-объекте → находка с рендером метки, без suppress.

## 4. CLI --mac + гейтинг

- [x] 4.1 `--mac` на `audit fs`/`expose` (cli_def.rs). В open-билде (только NullMacProvider) `--mac`
      → честный отказ «no MAC backend in this build», ненулевой код.
- [x] 4.2 Выбор провайдера в `cli/audit.rs`: слинкованный реальный (enterprise, через seam) vs Null;
      не-MAC хост → no-op, нота DAC-only. (Реальный выбор бэкенда — точка инжекта overlay; здесь только
      seam + Null-ветка + отказ.)
- [x] 4.3 Unit: `--mac` в open-билде отказывает; без `--mac` — Null, поведение как сегодня.

## 5. Контракт, тесты, верификация

- [x] 5.1 Golden `contract/exposure-report.schema.json` расширить полем `mac` (реген `UPDATE_CONTRACT=1`),
      `tests/contract.rs` зелёный. Bump VERSION если конвенция требует (аддитивное nullable-поле — скорее
      нет).
- [x] 5.2 Полный прогон `cargo test` + `cargo clippy --all-targets --all-features` зелёные, ноль warnings
      в exposure/. Снапшот-паритет: при NullMacProvider вывод текст/JSON не изменился vs pre-change.
- [x] 5.3 Док-заметка в README/audit.md: MAC-уточнение — enterprise-фича через инжектируемый провайдер;
      open-билд DAC-only; поле `mac` в выводе. (Трилингв — по конвенции.)

## Вне этого change (напоминание)

- Коммерческий `census_mac_parsec` (libpdp read-only: object_label/principal_contexts/permits по
  Biba/BLP, VM-пиннинг правил) + `census-enterprise` overlay-каркас — отдельный приватный трек.
- Будущий `census_mac_selinux` под тем же `MacProvider` — без правок open-ядра.
