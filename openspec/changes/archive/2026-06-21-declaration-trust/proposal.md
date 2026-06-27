# Proposal: declaration-trust

## Why

`census apply` сейчас применяет план только под `--trust-fs` (standalone, доверие
целостности ФС). Managed-путь — подпись декларации + anti-rollback — это заглушка
(`verify_trust` всегда возвращает «не доверено» без `--trust-fs`). Для парка под Control
нужен реальный fail-closed managed-режим: декларация подписана, проверяется до любых мутаций,
старую декларацию подсунуть нельзя (anti-rollback).

Census — отдельный продукт, но тот же парк/Control, что и Tessera. Tessera уже верифицирует
role-store manifest по подписи (Ed25519, монотонный `bundle_version`, fail-closed, whole-
bundle — `tessera/crates/tessera_core/src/role/manifest.rs`). Census переиспользует **ту же
схему доверия** (один корень доверия Control, единая крипто-конвенция), но в собственной
реализации (Census не зависит от tessera_core — отдельное репо; интероп на уровне байт
подписи: подпись ключом Control проходит у обоих).

Канон: `internal/specs/2026-06-18-census-core-spec.md` §9; §17 (форк «своя подпись vs
Tessera-manifest») — решён: переиспользовать схему, своя имплементация.

## What Changes

- Новая capability **declaration-trust**: реальная верификация доверия декларации в managed-
  режиме, замена заглушки в `verify_trust`.
- **Подпись Ed25519**: декларация несёт строку `signature = "<hex>"`; подпись покрывает байты
  декларации с **удалённой строкой `signature`** (та же канонизация, что Tessera manifest).
  Проверка — до любых мутаций/снапшота (fail-closed); невалидно → отказ.
- **Anti-rollback**: поле `version` декларации монотонно; Census персистит последний
  применённый `version` (`/var/lib/census/declaration.version`, root-only); декларация с
  `version` ≤ применённого отвергается. Повтор того же `version` — допустим как no-op
  (идемпотентность apply уже есть).
- **Trust-anchor**: публичный ключ Control пинится на устройстве (`/etc/census/trust.pub`,
  root-only). Census читает его для верификации. Доставка/ротация ключа — вне scope (как у
  Tessera: пин при enrollment).
- **Два режима** (паритет Tessera role-store): managed (подпись+anti-rollback) и standalone
  (`--trust-fs`, уже есть — доверие правам ФС). Без одного из двух доверий — apply отказывает.
- **GOST — будущее**: алгоритм подписи pluggable; Ed25519 сейчас, ГОСТ-вариант — расширение
  (как `verify_signature` у Tessera).

## Non-goals (отдельно)

- Доставка/ротация trust-anchor и деклараций через Control (census-enterprise).
- Подпись на стороне Control / тулинг подписания (вне устройства).
- ГОСТ-крипта (будущее расширение).
- Per-slice хэши role-store из декларации (Census читает role-store с диска под тем же
  доверием ФС; пиннинг хэшей role-store — возможное будущее, не здесь).
