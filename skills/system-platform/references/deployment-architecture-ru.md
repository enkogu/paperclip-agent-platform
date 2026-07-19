# Архитектура развёртывания

## Единственный путь установки

```text
./install.sh
    │
    ├── preflight.sh    проверка env и SSH
    ├── host.sh         Docker/Compose и server runtime env
    ├── compose.sh      контейнеры, сети, volumes, healthchecks
    ├── provision.sh    аккаунты, токены, workflows и связи
    ├── cloudflare.sh   firewall, DNS, Tunnel и Access
    └── verify.sh       реальные canary и E2E
```

`install.sh` — простой Bash-индекс и единственный источник порядка. В системе
нет собственного deployment engine, immutable snapshot manager, checkpoint,
resume или автоматического rollback. Повторный запуск безопасен за счёт
идемпотентности Compose и provisioning API.

Docker Compose не запускает наши скрипты. Наоборот, `compose.sh` вызывает:

```bash
docker compose \
  --env-file /root/.config/mte-secrets/platform.env \
  -f /opt/mte-platform/deployment/compose.yaml \
  up -d --wait
```

`deployment/compose.yaml` агрегирует owner-scoped определения из
`deployment/services/*/compose.yaml`. Он использует только готовые образы,
закреплённые digest. Обычный deploy не выполняет `down`, не удаляет volumes и
не пересобирает upstream-приложения.

## Конфигурация

Оператор заполняет один приватный файл:

```text
config/platform.env
```

Это единственный редактируемый source of truth. Он импортируется
fill-only в root-owned server runtime файл:

```text
/root/.config/mte-secrets/platform.env
```

Туда же один раз добавляются сгенерированные пароли, токены, порты, image
digests и ID созданных ресурсов. Сервисы читают эту runtime-материализацию,
но оператор меняет только `config/platform.env`.

## Runtime и provisioning

Compose владеет контейнерными компонентами: PostgreSQL, PostgREST, Kestra,
9Router, ToolHive, Mattermost, SearXNG, Firecrawl и observability. Paperclip,
Daytona и Hermes имеют отдельные официальные host/plugin runtime contracts и
устанавливаются из `provision.sh` после готовности контейнерных API.

Provisioning-группы:

```text
paperclip
kestra
toolhive-profiles
mattermost-hermes
notion-postgres
daytona-harness-auth
```

Каждая группа сначала читает текущее состояние через API, затем создаёт или
обновляет только недостающее. Секреты передаются только через канонические
references и Paperclip secret scopes, не через аргументы команд.

## Быстрая итерация

```bash
./test.sh quick
./install.sh compose firecrawl
./test.sh smoke firecrawl
```

Перед релизом:

```bash
make release-check
./install.sh verify
```

`quick` не обращается к серверу. `smoke` проверяет живой компонент без полного
LLM workflow. `verify` запускает реальный Paperclip → Daytona → Codex/Claude/Pi
→ 9Router/MiniMax → GitHub цикл и проверяет cleanup.

Полная чистая установка выполняется только на явно выбранном одноразовом
сервере. Установщик намеренно не предоставляет destructive reset.
