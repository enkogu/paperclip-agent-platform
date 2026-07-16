# Реестр связей платформы

Канонический реестр — `config/connections.yaml`. Этот документ описывает его правила,
но не дублирует все строки: ID, owner, auth, exposure и check должны читаться из
machine-readable файла.

```bash
./platform connections export
./platform connections check
```

`export` создаёт evidence-снимок. `check` обязан проверить все обязательные
связи текущего профиля; условные integrations получают явный conditional status,
а не ложный `passed`.

## Exposure classes

| Класс | Значение |
|---|---|
| `internal` | приватная Docker/service network, host port не публикуется |
| `loopback` | bind только на `127.0.0.1` сервера |
| `human` | Cloudflare Access плюс auth приложения |
| `service` | Cloudflare Service Auth и отдельный token |
| `webhook` | только точный path, signature/state/replay protection и rate limit |
| `egress` | только исходящий вызов провайдера |
| `none` | внешнего route и DNS record нет |

## Основные группы связей

| ID | Контракт |
|---|---|
| C001-C019 | Kestra, Paperclip, runners, Hermes, 9Router, ToolHive и profile reconciliation |
| C020-C039 | Activepieces, OAuth, Firecrawl, SearXNG, Postgres/Notion, Mattermost, Telegram и provisioning |
| C040-C050 | OTel, Victoria*, Grafana, alerting и observability provisioning |
| C060-C071 | SSH/Dokploy/Cloudflare, application data services, deployment idempotency и canonical config |
| C072-C080 | Paperclip/Daytona environments, harness secrets, real LLM/GitHub E2E и cleanup |

## Ключевые пути

```text
Kestra -> Paperclip adapter POST /v1/runs -> Paperclip Issue/run
Paperclip -> Daytona provider -> isolated workspace -> harness
harness -> profile 9Router route -> LLM
harness -> profile ToolHive vMCP -> reviewed tools
Paperclip/Activepieces -> scoped PostgREST -> PostgreSQL SSOT
PostgreSQL outbox -> mte.notion.connector -> Notion projection
applications -> OTel -> Victoria* -> Grafana/Alertmanager
operator -> Cloudflare -> declared UI only
Mattermost / Telegram -> official Hermes gateway -> native LLM loop
Hermes native API -> 9Router -> native terminal -> platform status
```

## Network zones

- control: Kestra, Paperclip и официальный Hermes gateway;
- execution: Paperclip provider, Daytona workspaces;
- LLM: harnesses/Hermes to 9Router;
- tool: profile gateways, ToolHive and MCP workloads;
- data: PostgreSQL, PostgREST and scoped consumers;
- integrations/search/comms: Activepieces, Firecrawl, SearXNG, Mattermost;
- telemetry: OTel, Victoria backends, Grafana and alerting;
- per-application data networks: only the application and its DB/queue.

Hermes не имеет отдельного platform bridge. Проверяемая цепочка — native API
официального gateway → LLM loop → 9Router → native terminal → read-only status
платформы. Mattermost и Telegram подключаются встроенными интеграциями Hermes,
а unrestricted host-operator mode проверяется отдельно по systemd unit и
явно установленной sudoers policy.

## Обязательные инварианты

1. У обязательной связи есть owner, auth class, exposure и исполняемый check.
2. Raw credential указывается только ссылкой и не попадает в evidence.
3. Порт нельзя публиковать без exposure declaration и Cloudflare policy.
4. Harness key и ToolHive bearer одного профиля отвергаются на другом профиле.
5. Database, Docker socket, ToolHive control, Daytona и raw telemetry недоступны
   через публичный edge.
6. Notion является egress provider: у него нет локального origin/hostname.
7. NocoDB/NocoDocs и Baserow/Wiki.js не входят в обязательный registry active
   profile, пока их профили `selectable: false`.
8. E2E считается завершённым только после cleanup sandbox/workspace/PR/branch.

Добавление интеграции начинается со строки в `config/connections.yaml`, затем получает
manifest/provisioning, smoke/negative check, telemetry и cleanup contract.
