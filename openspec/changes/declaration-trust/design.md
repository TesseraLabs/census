# Design: declaration-trust

## Контекст

`apply::run` уже вызывает `verify_trust(decl, opts)` ПЕРВЫМ шагом (до plan/snapshot/мутаций).
Сейчас managed-ветка — заглушка («не доверено» без `--trust-fs`). Этот change даёт реальную
managed-проверку: подпись Ed25519 + anti-rollback, fail-closed. Standalone (`--trust-fs`)
остаётся как есть.

## Решения

### Р1. Схема подписи — переиспользуем Tessera-manifest, своя реализация

Та же крипто-конвенция, что `tessera_core/role/manifest.rs` (один корень доверия Control):
- **Ed25519**, чистый EdDSA (без внешнего дайджеста).
- Подпись покрывает байты декларации с **полностью удалённой строкой `signature`**
  (строка, чей первый непробельный токен — `signature`, за ним `=`), включая её перевод
  строки. Канонизация байт-в-байт, как у Tessera.
- fail-closed: любая невалидность → отказ всей декларации.

Реализация — **в census, не зависимость от tessera_core** (отдельное репо). Крипто —
`ed25519-dalek` (pure-Rust, без системного openssl). Интероп — на уровне байт: подпись,
сделанная ключом Control (любым Ed25519-signer, включая openssl Tessera), верифицируется
`ed25519-dalek`. ГОСТ — будущее расширение (точка `verify_signature` pluggable, как у Tessera).

### Р2. Trust-anchor

Публичный ключ Control пинится на устройстве: `/etc/census/trust.pub` (root-only, 0644).
Формат — **hex 32-байтного raw Ed25519 public key** (lib-агностично). Census читает его для
верификации. Доставка/ротация/пин — вне scope (как у Tessera: пин при enrollment).
⚠ Координация: формат on-disk trust-anchor должен совпасть с тем, как Control раскладывает
ключ для Tessera (если Tessera хранит PEM/SPKI — согласовать единый формат или конвертацию).

### Р3. Anti-rollback

Поле `version` декларации монотонно (уже есть в схеме, валидируется ≥1). Census персистит
последний **успешно применённый** `version` в `/var/lib/census/declaration.version`
(root-only). Правила:
- `version` < персиста → **отказ** (anti-rollback: подсунута старая декларация).
- `version` == персиста → допустимо (идемпотентный повторный apply; план будет пуст).
- `version` > персиста → принять; персист обновляется **после успешного apply** (как managed-
  реестр — чтобы откат-на-сбое не двигал счётчик).

### Р4. Точка интеграции (fail-closed порядок)

`verify_trust(decl_bytes, opts) -> Result<TrustDecision, TrustError>`:
1. если `--trust-fs` → `Trusted(Standalone)` + лог (как сейчас).
2. иначе managed: прочитать trust.pub → извлечь `signature` из байт → канон-payload →
   Ed25519 verify; провал → `Err` (fail-closed).
3. anti-rollback: прочитать персист-версию; `decl.version < persisted` → `Err`.
4. ок → `Trusted(Managed { version })`.
Вызов — уже первым в `apply::run`, ДО snapshot/мутаций. Персист версии — отдельным шагом
после успеха apply (рядом с записью реестра).

`verify_trust` принимает СЫРЫЕ байты декларации (для канонизации подписи), не только
распарсенную структуру. `Declaration` получает поле `signature: Option<String>`
(`#[serde(default)]`), чтобы строгий парсер (`deny_unknown_fields`) не падал на ней.

## Безопасность (threat-анализ change'а)

- **Подделка декларации** (создать привилегированную учётку / снести rescue): Ed25519-подпись
  по ключу Control; без валидной подписи (и без `--trust-fs`) — отказ до мутаций. Закрыто Р1.
- **Откат декларации** (подсунуть старую валидно-подписанную): монотонный `version` + персист.
  Закрыто Р3.
- **Подмена trust-anchor** (заменить `/etc/census/trust.pub` своим ключом): требует root-write
  в `/etc/census/` — та же поверхность, что и `--trust-fs` (доверие правам ФС). Митигация —
  права 0644 root, целостность образа; пиннинг/ротация ключа — Control/enrollment (вне scope).
- **Downgrade к `--trust-fs`** (заставить оператора/скрипт обойти подпись): `--trust-fs` —
  явный флаг, логируется; кто может задать CLI-флаги уже root. Дефолт fail-closed: нет флага +
  нет валидной подписи → отказ.
- **Компрометация ключа Control**: вне scope (ротация trust-anchor — Control); отзыв
  старого ключа — будущее (как у Tessera trust-chain).
- **Мутация персист-файла версии** (сбросить anti-rollback): root-only `/var/lib/census/`;
  та же поверхность root. Не хуже Tessera bundle.version.

Дельта в workspace `threat-model.md` (§Census) — отдельным doc-проходом (трекается).

## Тестирование

- **Unit**: канонизация (удаление строки `signature`, байт-в-байт); Ed25519 verify (валид/
  подделка/битая подпись) на тестовой паре ключей; anti-rollback (version < / == / > персиста);
  fail-closed (managed без подписи → отказ; trust.pub отсутствует → отказ); `--trust-fs`
  по-прежнему работает; `Declaration` парсит строку `signature` (deny_unknown_fields не падает).
- **Контейнер** (дополнить harness): apply подписанной декларации без `--trust-fs` проходит;
  apply неподписанной без флага — отказ до мутаций; реплей старой версии — отказ; персист
  версии двигается только после успеха.

## Открытые вопросы

- Точный on-disk формат trust-anchor у Control (hex-raw vs PEM/SPKI) — согласовать с Tessera
  при интеграции с Control (Р2). Дефолт здесь — hex 32-байт raw.
- Подпись CRL/role-store хэшей из декларации (как Tessera manifest пинит хэши слайсов) —
  вынесено в non-goals; решить при доставке role-store через Control.
