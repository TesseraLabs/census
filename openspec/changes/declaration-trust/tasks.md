# Tasks: declaration-trust

## 1. Крипто и канонизация

- [x] 1.1 Добавить зависимость `ed25519-dalek` (verify) + `hex` в Cargo.toml
- [x] 1.2 `trust.rs`: `signed_payload(bytes) -> Vec<u8>` — удалить строку `signature` (первый
  непробельный токен `signature`, затем `=`), байт-в-байт, включая её `\n`
- [x] 1.3 Unit: канонизация — строка удалена точно; payload без неё байт-идентичен; отсутствие
  строки `signature` → ошибка/обработка

## 2. Trust-anchor + верификация подписи

- [x] 2.1 `trust.rs`: чтение `/etc/census/trust.pub` (hex 32-байт raw Ed25519), путь injectable
- [x] 2.2 `verify_ed25519(pubkey, payload, sig_hex) -> Result<(), TrustError>` через ed25519-dalek
- [x] 2.3 `Declaration`: поле `signature: Option<String>` (`#[serde(default)]`), не ломает
  `deny_unknown_fields`; извлечение подписи из распарсенной/сырой формы
- [x] 2.4 Unit: валид/подделка/битый hex/нет trust.pub → корректный TrustError (fail-closed)

## 3. Anti-rollback

- [x] 3.1 `trust.rs`: `last_applied_version(dir)` / `persist_version(dir, v)` —
  `/var/lib/census/declaration.version`, root-only, путь injectable
- [x] 3.2 Логика: `version < persisted` → отказ; `== ` → ок (no-op); `>` → ок
- [x] 3.3 Unit: три случая версии; персист двигается только при вызове persist

## 4. Интеграция в verify_trust + apply

- [x] 4.1 Заменить заглушку managed в `verify_trust`: trust.pub → подпись → anti-rollback;
  `--trust-fs` ветка без изменений; принимает сырые байты декларации
- [x] 4.2 `TrustDecision` несёт режим (Standalone | Managed{version})
- [x] 4.3 `apply::run`/`cli`: persist_version ПОСЛЕ успешного apply (рядом с записью реестра),
  только для Managed-режима
- [x] 4.4 Unit (FakeProvisioner): managed без подписи → отказ до snapshot; реплей версии →
  отказ; успех → персист обновлён; сбой фазы → персист не тронут

## 5. Контейнер-интеграция (дополнить harness)

- [x] 5.1 Сгенерировать тестовую Ed25519-пару, положить pub в `/etc/census/trust.pub`,
  подписать декларацию (openssl — заодно интероп openssl↔dalek)
- [x] 5.2 Сценарий: подписанная декларация без `--trust-fs` → apply проходит
- [x] 5.3 Сценарий: неподписанная без флага → отказ, мутаций нет
- [x] 5.4 Сценарий: реплей меньшей версии → отказ; персист двигается только после успеха

## 6. Канон-синхронизация

- [x] 6.1 core-spec §9/§17: схема Tessera-manifest переиспользована, своя реализация
  ed25519-dalek; trust.pub hex-raw; persist declaration.version
- [x] 6.2 master-code-reviewer (H1 canon-parity + M1/M2/L1 hardening пофикшены)
