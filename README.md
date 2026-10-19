# durio-chat — сервер dur.io

**English summary.** Backend of the **dur.io** messenger (Rust): REST API, WebSocket events, file server, push,
cron and voice ingress. A fork that adds end-to-end encryption (beta) for DMs and groups, push routing for
several servers and accounts, instance admins who can end user sessions, 100 MB attachments and 1080p video.
Deploy it with [durio-self-hosted](https://github.com/DakarXYZ/durio-self-hosted). Licensed under AGPL-3.0.

Бэкенд мессенджера **dur.io**: REST API, WebSocket-события, файловый сервер, push, фоновые задачи и приём
событий звонков. Автор и владелец форка — DakarX ([GitHub DakarXYZ](https://github.com/DakarXYZ)).

Основано на [stoatchat/stoatchat](https://github.com/stoatchat/stoatchat). dur.io — независимый форк и не связан
с проектом Stoat; название и логотип Stoat — товарные знаки их владельцев. Имена крейтов (`revolt-*`) и путь
discovery `/.well-known/stoat` оставлены как в оригинале: это совместимость, а не бренд.

## Что добавляет форк

**Сквозное шифрование (E2EE, бета) личных сообщений и групп.** Сервер — только почтальон: открытый текст и
закрытые ключи до него не доходят. Каналы серверов (гильдий) не шифруются.

- Маршруты `/e2ee/*` в форме Matrix CS API: ключи устройств и одноразовые ключи (`keys/upload|query|claim|count`),
  ящик `to_device` (`GET` + `ack`), зашифрованный бэкап ключей и секретное хранилище; MFA на удаление бэкапа.
  Устройство E2EE = сессия входа: выход, отзыв сессии и удаление аккаунта удаляют и устройство.
- `PUT /channels/<id>/encryption` — необратимое включение шифрования ЛС или группы, системное сообщение
  `encryption_enabled`. В зашифрованном канале: сообщения и правки только в виде конверта v1 (`encrypted`),
  нет embeds, поиска, упоминаний, маскарада, ботов и вебхуков; push без текста («Новое сообщение от X»).
- Зашифрованные вложения в autumn (`?encrypted=true`): без превью, метаданных и определения типа.
- Старые клиенты вместо зашифрованного сообщения видят заглушку (`features.e2ee.legacy_placeholder`), а не
  падают. Все новые поля API — необязательные.
- Флаг `[features.e2ee]` (по умолчанию выключен) и описание в `GET /`; миграция БД 56 (коллекции `e2ee_*`);
  очистка брошенных данных в crond; ключи, шифротекст и секреты не попадают в логи.
- Крипто-ядро клиентов — отдельный репозиторий [durio-crypt](https://github.com/DakarXYZ/durio-crypt); бэкенд от
  него не зависит.

**Несколько серверов и аккаунтов.** FCM-push несёт `instance` (канонический адрес API) и `recipient`, чтобы клиент
доставил уведомление нужному аккаунту на нужном сервере.

**Администрирование из клиента.** `[api.admins] users` (и пользователи с `privileged`) получают маршруты
`/admin`: найти пользователя по id или `имя#1234`, посмотреть его сеансы и завершить один или все — например,
после потери телефона. Каждое действие пишется в лог с id администратора.

**Лимиты по умолчанию.** Вложения до 100 МБ (тело запроса — 105 МБ), видео в звонках и демонстрация экрана —
до 1920×1080; кэш autumn в памяти уменьшен до 512 МиБ, чтобы помещаться в лимит контейнера.

**Надёжность** (найдено нагрузочными и хаос-тестами): переподключение к RabbitMQ и Redis после рестарта,
идемпотентная отправка сообщений (`Idempotency-Key` = `nonce`), закрытие «мёртвых» сокетов в bonfire, повтор
гонки при обновлении непрочитанного; исправления reference-драйвера БД.

**Сборка и выпуск.** Свои образы `ghcr.io/dakarxyz/durio-<service>` (только amd64), зонд healthcheck для
distroless-образов, CI на GitHub-hosted раннерах, версия `0.16.0+fork.N`.

## Крейты

| Крейт | Путь | Назначение |
| --- | --- | --- |
| `core/config` | [crates/core/config](crates/core/config) | конфигурация, дефолты — `Revolt.toml` |
| `core/database` | [crates/core/database](crates/core/database) | модели и реализации БД (MongoDB и reference) |
| `core/files` | [crates/core/files](crates/core/files) | S3 и шифрование файлов |
| `core/models` | [crates/core/models](crates/core/models) | модели API (попадают в OpenAPI) |
| `core/permissions` | [crates/core/permissions](crates/core/permissions) | права |
| `core/presence` | [crates/core/presence](crates/core/presence) | присутствие пользователей |
| `core/result` | [crates/core/result](crates/core/result) | ошибки |
| `core/coalesced` | [crates/core/coalesced](crates/core/coalesced) | объединение запросов |
| `delta` | [crates/delta](crates/delta) | REST API (`/e2ee`, `/admin` — наши маршруты) |
| `bonfire` | [crates/bonfire](crates/bonfire) | WebSocket-события |
| `services/autumn` | [crates/services/autumn](crates/services/autumn) | файловый сервер |
| `services/january` | [crates/services/january](crates/services/january) | прокси для превью ссылок |
| `services/gifbox` | [crates/services/gifbox](crates/services/gifbox) | прокси GIF (в нашем развёртывании выключен) |
| `daemons/crond` | [crates/daemons/crond](crates/daemons/crond) | фоновая очистка данных |
| `daemons/pushd` | [crates/daemons/pushd](crates/daemons/pushd) | push (FCM, APNs, Web Push) |
| `daemons/voice-ingress` | [crates/daemons/voice-ingress](crates/daemons/voice-ingress) | вебхуки LiveKit |

## Разработка

Rust 1.92 (`rust-toolchain.toml`). Собирать и тестировать — в Linux (WSL2 Ubuntu или Docker): на Windows нативно
мешают `mold`, `dav1d` и ffmpeg.

### Linux / WSL2

Нужны mise, Docker и Git.

```bash
mise install                 # тулчейн: rust, nextest, node, pnpm
mise docker:start            # MongoDB (replica set), Redis, MinIO, RabbitMQ, Maildev, LiveKit
mise build                   # cargo build
mise check                   # cargo clippy — без новых предупреждений
mise test                    # cargo nextest run, TEST_DB=REFERENCE (в памяти)
TEST_DB=MONGODB mise test    # те же тесты на MongoDB
cp livekit.example.yml livekit.yml
mise start                   # все сервисы локально
mise docker:stop
```

Порты локального окружения:

| Сервис | Порт |
| --- | :-: |
| MongoDB | 27017 |
| Redis | 6379 |
| MinIO | 14009 |
| Maildev | 14025, 14080 |
| RabbitMQ | 5672, 15672 |
| Grafana LGTM (OTLP) | 13000, 4318 |
| `delta` | 14702 |
| `bonfire` | 14703 |
| `autumn` | 14704 |
| `january` | 14705 |
| `gifbox` | 14706 |

Дефолтная конфигурация — `Revolt.toml`; свои настройки — в `Revolt.overrides.toml` (не коммитить). Адрес MongoDB
для тестов задаётся `REVOLT__DATABASE__MONGODB=...`. Письма подтверждения при локальной регистрации — в Maildev,
http://localhost:14080. Часть кода upstream использует транзакции — MongoDB нужна в режиме replica set (локальный
compose так и запускает её).

### Windows (только Docker)

Базовый образ сборщика — тот же, что в CI образов:

```bash
scripts/durio/build-images.sh                 # durio-base:local и образы durio-<service>:local
```

Для `cargo` в контейнере — образ на его основе с rustfmt, clippy и nextest (этот Dockerfile — вне репозитория,
`docker build -t durio-rust-dev:local -f <файл> .`):

```dockerfile
FROM durio-base:local
RUN rustup component add --toolchain 1.92.0 rustfmt clippy rust-analyzer
ADD https://get.nexte.st/0.9/linux /tmp/nextest.tar.gz
RUN tar zxf /tmp/nextest.tar.gz -C /usr/local/cargo/bin && rm /tmp/nextest.tar.gz
```

```bash
# Git Bash, из корня репозитория; кэш сборки и реестра — в томах Docker
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src" -v durio-cargo-target:/target \
    -v durio-cargo-registry:/usr/local/cargo/registry -w /src -e CARGO_TARGET_DIR=/target \
    durio-rust-dev:local sh -c 'cargo nextest run -j 6 -p revolt-delta'
```

Больше `-j 6` Docker Desktop может не выдержать по памяти. Тестам на MongoDB нужны MongoDB (replica set), Redis
и RabbitMQ в той же сети Docker. Без Maildev и MinIO падают тесты почты и S3 в `revolt-files` — это ожидаемо.

### Правила для изменений

- Новые поля API — `Option` + `#[serde(skip_serializing_if)]`: старые клиенты не должны ломаться.
- Новая модель БД — обе реализации: `ops/mongodb.rs` и `ops/reference.rs`; миграции — в
  `crates/core/database/src/models/admin_migrations/`.
- Каждый новый маршрут — с тестом через `TestHarness`; ошибки — через `create_error!`, без `unwrap()`.
- `cargo fmt --all --check` в upstream не чистый — форматировать только свои файлы.
- Никогда не логировать открытый текст, ключи и сессии E2EE.

### Переменные окружения

Список неполный.

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `RUST_LOG` | `info` | фильтр логов, например `info,revolt_autumn=debug` |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | | OTLP/HTTP для логов |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | | OTLP/HTTP для трасс |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | | OTLP/HTTP для метрик |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4318` | один коллектор, добавляет `/v1/{logs,traces,metrics}` |
| `OTEL_RESOURCE_ATTRIBUTES` | | доп. атрибуты, например `deployment.environment.name=staging` |
| `OTEL_TRACES_SAMPLER` | `parentbased_always_on` | сэмплер трасс |
| `OTEL_TRACES_SAMPLER_ARG` | `1.0` | доля сэмплирования |
| `REVOLT__<секция>__<ключ>` | | любой ключ конфигурации, сильнее файлов (так в развёртывании задаются секреты) |

## Выпуск и развёртывание

- Версия крейтов и `revolt` в `GET /` — `0.16.0+fork.N` (`version.txt`); git-тег — `v0.16.0-fork.N`.
- Тег → `.github/workflows/durio-images.yaml` собирает 8 образов `ghcr.io/dakarxyz/durio-<service>:0.16.0-fork.N`
  (amd64) и прогоняет smoke-тест версии. Локально то же — `scripts/durio/build-images.sh --tag <тег> --smoke`.
- `.github/workflows/durio-ci.yaml` — clippy, сборка и тесты на reference и MongoDB.
- Сервер разворачивается репозиторием [durio-self-hosted](https://github.com/DakarXYZ/durio-self-hosted)
  (пошагово — `docs/deploy-contabo.md` там).

Ошибки и предложения — [issues](https://github.com/DakarXYZ/durio-chat/issues).

## Лицензия

[GNU Affero General Public License v3.0](LICENSE), как у оригинала. Отдельные крейты могут иметь свои лицензии —
см. их `Cargo.toml` и `LICENSE`. Copyright © DakarX для изменений dur.io; исходный код оригинала — его авторов.
