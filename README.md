# Antivirus Security Baseline

Spring Boot backend with:
- JWT authentication (`access` + `refresh` tokens)
- RBAC authorization (`ROLE_USER`, `ROLE_ADMIN`)
- PostgreSQL integration (`antivirus`, `postgres/postgres`)
- HTTPS with a certificate chain of 3 links (Root CA -> Intermediate CA -> Server cert)
- GitHub Actions CI (compile, test, package, upload artifact)

## Requirements

- Java 17+
- Maven 3.9+
- PostgreSQL 14+
- OpenSSL in PATH (for certificate generation script)

## Environment

Copy `.env.example` to `.env` (or set environment variables directly):

- `DB_URL` (default `jdbc:postgresql://localhost:5432/antivirus`)
- `DB_USERNAME` (default `postgres`)
- `DB_PASSWORD` (default `postgres`)
- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `TLS_KEYSTORE_PATH` (default `certs/server-keystore.p12`)
- `TLS_KEYSTORE_PASSWORD`
- `TLS_KEY_ALIAS`

Optional seed credentials:
- `APP_SEED_ADMIN_USERNAME`, `APP_SEED_ADMIN_PASSWORD`
- `APP_SEED_USER_USERNAME`, `APP_SEED_USER_PASSWORD`

## PostgreSQL setup

Create database:

```sql
CREATE DATABASE antivirus;
```

User/password defaults are `postgres/postgres`.  
Schema is created via Flyway migration `src/main/resources/db/migration/V1__init.sql`.

## Generate certificate chain (3 links)

Run PowerShell script:

```powershell
./scripts/certs/generate-chain.ps1 -OutputDir certs -StudentId "1BIK22149" -KeystorePassword "changeit" -ServerAlias "server"
```

Generated files include:
- `certs/root-ca.crt` (Root CA)
- `certs/intermediate-ca.crt` (Intermediate CA)
- `certs/server.crt` (Server certificate)
- `certs/fullchain.pem` (full chain)
- `certs/server-keystore.p12` (PKCS12 keystore for Spring Boot)

`OU=1BIK22149` is embedded in subjects of generated certificates.

## Run

```powershell
mvn spring-boot:run
```

Service starts on `https://localhost:8443`.

## Auth endpoints

- `POST /api/auth/login`
  - body: `{"username":"admin","password":"admin12345"}`
- `POST /api/auth/refresh`
  - body: `{"refreshToken":"..."}`
- `POST /api/auth/logout`
  - body: `{"refreshToken":"..."}`

Protected examples:
- `GET /api/me` (any authenticated user)
- `GET /api/admin/ping` (requires `ROLE_ADMIN`)

## GitHub Actions CI

Workflow file: `.github/workflows/ci.yml`

Stages:
1. `compile` -> `mvn -DskipTests compile`
2. `test` -> `mvn test`
3. `package` -> `mvn -DskipTests package`
4. Upload artifact via `actions/upload-artifact`

### Required GitHub Secrets

- `JWT_ACCESS_SECRET`
- `JWT_REFRESH_SECRET`
- `DB_URL`
- `DB_USERNAME`
- `DB_PASSWORD`
- `TLS_KEYSTORE_BASE64` (base64 of `server-keystore.p12`)
- `TLS_KEYSTORE_PASSWORD`
- `TLS_KEY_ALIAS`

### Keystore in GitHub Secrets

Create base64 payload locally:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("certs/server-keystore.p12"))
```

Put this value into `TLS_KEYSTORE_BASE64`.  
Workflow restores it to `certs/server-keystore.p12` during `package` job.

## Digital signature module (ЭЦП)

Модуль ЭЦП подписывает ответы лицензии (`Ticket`) по схеме:

```
Ticket -> JsonCanonicalizer (RFC 8785) -> UTF-8 bytes -> SHA256withRSA -> Base64
```

Компоненты в пакете `com.antivirus.signature`:

- `SignatureProperties` — `@ConfigurationProperties("signature")` (путь к keystore, alias, пароли, алгоритм).
- `SignatureKeyProvider` — однократная загрузка приватного ключа и сертификата.
- `JsonCanonicalizer` — детерминированное представление JSON по RFC 8785.
- `SignatureService` — фасад `sign(Object)` и `verify(Object, base64)`.

Подключение к лицензии: [`TicketSigningService`](src/main/java/com/antivirus/ticket/TicketSigningService.java) делегирует подпись в `SignatureService`. Контроллер `/api/licenses/activate|check|renew` возвращает `TicketResponse{ ticket, digitalSignature }`.

### Генерация хранилища подписи

Отдельное хранилище, не пересекающееся с TLS keystore:

```powershell
keytool -genkeypair -alias app-signing -keyalg RSA -keysize 2048 `
  -dname "CN=antivirus-signing" -validity 3650 `
  -keystore certs/signing-keystore.p12 -storetype PKCS12 `
  -storepass changeit -keypass changeit

keytool -exportcert -alias app-signing -rfc `
  -keystore certs/signing-keystore.p12 -storepass changeit `
  -file certs/signing-public.pem
```

### Переменные окружения

- `SIGNATURE_KEYSTORE_PATH` (по умолчанию `certs/signing-keystore.p12`)
- `SIGNATURE_KEYSTORE_TYPE` (по умолчанию `PKCS12`)
- `SIGNATURE_KEYSTORE_PASSWORD`
- `SIGNATURE_KEY_ALIAS` (по умолчанию `app-signing`)
- `SIGNATURE_KEY_PASSWORD` (если пусто — используется `SIGNATURE_KEYSTORE_PASSWORD`)
- `SIGNATURE_ALGORITHM` (по умолчанию `SHA256withRSA`)

### GitHub secrets и variables для ЭЦП

Секреты:

- `SIGNATURE_KEYSTORE_BASE64` — base64 от `signing-keystore.p12`:
  ```powershell
  [Convert]::ToBase64String([IO.File]::ReadAllBytes("certs/signing-keystore.p12"))
  ```
- `SIGNATURE_KEYSTORE_PASSWORD`, `SIGNATURE_KEY_ALIAS`, `SIGNATURE_KEY_PASSWORD`.

Переменные (Settings -> Secrets and variables -> Actions -> Variables):

- `SIGNATURE_PUBLIC_KEY` — содержимое `certs/signing-public.pem` (PEM с заголовком `-----BEGIN CERTIFICATE-----`). Это публичный ключ для верификации подписи на стороне клиента.

В CI workflow ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) шаг `Materialize signing keystore from GitHub Secret` восстанавливает `certs/signing-keystore.p12` из `SIGNATURE_KEYSTORE_BASE64`, а шаг `Export signing public key from CI variable` пишет `certs/signing-public.pem` из `vars.SIGNATURE_PUBLIC_KEY`.

### Postman (проверка ЭЦП вручную)

1. Импорт: [`postman/antivirus-signature-ecp.postman_collection.json`](postman/antivirus-signature-ecp.postman_collection.json) и опционально environment [`postman/antivirus-local.postman_environment.json`](postman/antivirus-local.postman_environment.json).
2. Postman → Settings → **SSL certificate verification: OFF**.
3. Запустить Collection Runner по папкам `0` → `1` → `2` (сверху вниз).

## Malware signatures API

REST-модуль управления антивирусными сигнатурами (пакет `com.antivirus.malware`) реализует
8 операций по методичке. На каждое создание / изменение / удаление пересчитывается
ЭЦП через тот же `SignatureService` (см. раздел выше).

| Метод | Путь | Роль | Что делает |
|-------|------|------|------------|
| GET | `/api/signatures` | USER+ | Полная выгрузка (только `ACTUAL`) |
| GET | `/api/signatures/increment?since=ISO8601` | USER+ | Все записи с `updatedAt > since`, включая `DELETED` |
| POST | `/api/signatures/by-ids` | USER+ | Выборка по списку UUID |
| POST | `/api/signatures` | ADMIN | Создание (status=ACTUAL, audit `CREATED`) |
| PUT | `/api/signatures/{id}` | ADMIN | Обновление (snapshot в history, audit `UPDATED` с fieldsChanged) |
| DELETE | `/api/signatures/{id}` | ADMIN | Логическое удаление (status=DELETED, snapshot в history, audit `DELETED`) → 204 |
| GET | `/api/signatures/{id}/history` | ADMIN | Все версии записи, отсортированы по `versionCreatedAt desc` |
| GET | `/api/signatures/{id}/audit` | ADMIN | Журнал действий, отсортирован по `changedAt desc` |

Подписываются ровно поля payload (`MalwareSignaturePayload`):
`threatName, firstBytesHex, remainderHashHex, remainderLength, fileType, offsetStart, offsetEnd, status`.
`updatedAt` и сама `digitalSignatureBase64` в подпись не входят — это требование методички.

Схема БД: миграция [`V4__malware_signatures.sql`](src/main/resources/db/migration/V4__malware_signatures.sql)
(таблицы `signatures`, `signatures_history`, `signatures_audit` + индексы).

### Postman (проверка модуля сигнатур)

1. Импорт: [`postman/antivirus-malware-signatures.postman_collection.json`](postman/antivirus-malware-signatures.postman_collection.json).
2. Запустить Collection Runner по папкам `1` → `2` → `3` → `4` (сверху вниз).
3. Тестовые скрипты в коллекции автоматически проверяют чек-лист методички:
   create/update пересчитывают подпись, delete логический, history и audit заполняются,
   полная выгрузка не содержит `DELETED`, инкремент содержит.
