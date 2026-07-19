# Реестр требований к release evidence

Канонический реестр — `config/acceptance-requirements.yaml`. Это список обязательных
проверок релиза, а не источник runtime topology. Topology и exposure принадлежат
`config/platform.yaml`; реестр фиксирует ожидаемый путь, auth/exposure assertion и
исполняемый evidence check для каждого требования.

```bash
./platform acceptance export
./platform acceptance check
```

`export` печатает machine-readable требования. `check` обязан проверить все
обязательные требования текущего профиля; условные integrations получают явный conditional status,
а не ложный `passed`.

## Exposure classes

| Класс | Значение |
|---|---|
| `internal` | приватная Docker/service network, host port не публикуется |
| `loopback` | bind только на `127.0.0.1` сервера |
| `human` | Cloudflare Access плюс auth приложения; это provisioned edge class |
| `service` | Cloudflare Access service token; это provisioned edge class |
| `webhook` | контракт integration owner: exact path, signature/state/replay и payload controls; current Cloudflare module не создаёт для него WAF, rate limit или route policy |
| `egress` | только исходящий вызов провайдера |
| `none` | внешнего route и DNS record нет |

## Основные группы требований

| ID | Контракт |
|---|---|
| C001-C012, C014-C019 | Kestra, Paperclip, runners, Hermes, 9Router, ToolHive и profile reconciliation |
| C023-C027 | Firecrawl, SearXNG и scoped data API |
| C029-C032 | Postgres/Notion projection, Mattermost notification и operator access |
| C033-C035 | Telegram/Mattermost Hermes, native terminal и mode-aware host operator policy |
| C036-C037, C039 | Provisioning data connectors, Mattermost и Kestra |
| C040-C050 | OTel, Victoria*, Grafana, alerting и observability provisioning |
| C060, C063-C071 | SSH/Compose/Cloudflare, application data services, deployment idempotency и canonical config |
| C072-C080 | Paperclip/Daytona environments, harness secrets, real LLM/GitHub E2E и cleanup |

## Ключевые пути

```text
Kestra -> native POST /api/companies/{company_id}/issues -> Paperclip Issue/run
Paperclip -> Daytona provider -> isolated workspace -> harness
harness -> profile 9Router route -> LLM
harness -> profile ToolHive endpoint -> reviewed tools when harness wiring exists
platform/Paperclip-side services -> scoped PostgREST -> PostgreSQL SSOT
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
- integrations/search/comms: Firecrawl, SearXNG, Mattermost;
- telemetry: OTel, Victoria backends, Grafana and alerting;
- per-application data networks: only the application and its DB/queue.

Hermes не имеет отдельного platform bridge. Проверяемая цепочка — native API
официального gateway → LLM loop → 9Router → native terminal → read-only status
платформы. Mattermost и Telegram подключаются встроенными интеграциями Hermes,
а host-operator policy проверяется отдельно по systemd unit и явно объявленному
operator mode.

## Reviewed semantic migration: C035

При миграции от `ConnectionRegistry` к `ReleaseEvidenceRegistry` C035 намеренно
изменён, а не перенесён побайтно: `auth: explicit-unrestricted-sudo` / `check:
hermes-host-operator` заменены на `auth: declared-operator-mode` / `check:
hermes-host-operator-policy`. Это reviewed hardening: verifier принимает
`unprivileged_service` без sudoers и допускает broad host repair только когда
он явно выбран и его policy доказана. Миграция не возвращает unrestricted sudo
как неявный или стандартный контракт.

## Обязательные инварианты

1. У обязательного требования есть проверяемый путь, auth class, exposure и исполняемый check.
2. Raw credential указывается только ссылкой и не попадает в evidence.
3. Порт нельзя публиковать без exposure declaration. Для текущих `human`/`service`
   routes Cloudflare Access policy обязателен; `webhook` нельзя считать
   защищённым edge route, пока owner отдельно не реализовал и не проверил policy.
4. Harness key и ToolHive bearer одного профиля отвергаются на другом профиле.
5. Database, Docker socket, ToolHive control, Daytona и raw telemetry недоступны
   через публичный edge.
6. Notion является egress provider: у него нет локального origin/hostname.
7. E2E считается завершённым только после cleanup sandbox/workspace/PR/branch.

Добавление интеграции начинается в её runtime owner (`config/platform.yaml` или
профильном контракте). Строка в `config/acceptance-requirements.yaml` добавляется,
когда для release gate определены smoke/negative evidence и cleanup contract.
