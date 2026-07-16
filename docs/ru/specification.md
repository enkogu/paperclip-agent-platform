# Спецификация Paperclip Agent Platform

## 1. Назначение

Self-hosted backend-платформа для централизованного запуска и наблюдения пула
агентов. Она должна поддерживать coding и non-coding workflows, показывать
task/run status, давать агентам воспроизводимое окружение и scoped tools, а
оператору — единый декларативный deployment и доказуемую диагностику.

## 2. Ответственность компонентов

| Задача | Компонент |
|---|---|
| Schedules, workflow, retries, approvals | Kestra |
| Issues, assignment, heartbeat, messages, run status | Paperclip |
| Изолированный workspace/sandbox lifecycle | Daytona |
| Harness runtime | Codex, Claude Code, Pi |
| LLM routing и profile keys | 9Router |
| MCP workloads и profile-private tool bundles | ToolHive |
| Automation/OAuth connectors | Activepieces |
| Search/crawl | SearXNG, Firecrawl |
| Operator gateway | Hermes |
| Communication/alerts | Mattermost; optional Telegram |
| Canonical data/documents | PostgreSQL + scoped PostgREST |
| Tables/documents projection | Notion connector |
| Deployment | Dokploy + indexed platform CLI |
| Edge | Cloudflare Tunnel/Access |
| Telemetry | OTel, Victoria*, Grafana, Alertmanager |

## 3. Агентские профили

Декларативный каталог `config/profiles/catalog.yaml` поставляет три профиля:

- `coding-daytona-codex`;
- `coding-daytona-claude`;
- `coding-daytona-pi`.

Профиль задаёт harness/adapter, Daytona environment/workspace mode, instructions
и skills, resource limits, runtime packages, 9Router secret ref, ToolHive
endpoint/bearer, MCP policy и auth policy. Persistent credentials и subscription
homes в образ не входят.

Каталог расширяем: специализация может быть coding, research, content или
операционной. Kestra workflow не должен зависеть от внутреннего loop harness.

## 4. Task/run lifecycle

1. Kestra schedule/API или Hermes создаёт работу.
2. Paperclip создаёт Issue/run и назначает profile.
3. Daytona создаёт workspace из выбранного environment/image.
4. Harness получает task, repo/worktree, runtime secret refs и tools.
5. Heartbeats/messages/status поступают в Paperclip; Kestra poll-ит terminal
   state и применяет workflow gates.
6. Artifacts и GitHub checks проверяются.
7. Cleanup закрывает/удаляет временный PR/branch, workspace и sandbox согласно
   E2E контракту.

Normalized adapter API использует `/v1/runs`: create, get, cancel, resume и
artifact access. Machine-readable native IDs остаются доступны для трассировки.

## 5. Data/content contract

Активный профиль — `postgres-notion`.

- PostgreSQL владеет canonical records/documents, ID, revision, hash и payload.
- PostgREST предоставляет scoped API разным consumers.
- Notion показывает таблицы и документы, но не становится источником истины.
- Leased outbox consumer выполняет idempotent projection и read-back checks.
- Agents пишут canonical data через PostgREST и читают Notion через ToolHive
  MCP; Notion write принадлежит только connector identity.

NocoDB/NocoDocs и Baserow/Wiki.js — non-selectable implementations connector
boundary. Их включение требует завершённого контракта и полного acceptance.

## 6. Конфигурация и deployment

Все live значения происходят из одного root-owned `platform.env`. Repository
хранит schema/examples; service/Dokploy/profile/tool/Cloudflare configs —
generated projections с source hash.

Поддерживаемая последовательность:

```bash
./platform plan --all
./platform preflight
./platform deploy --all
./platform status
./platform verify --all
./platform connections check
```

Полный deploy выполняет 39 упорядоченных шагов и проверяет повторный apply для
ключевых reconcilers. Resume разрешён только по evidence исходного run без
изменения source.

## 7. Security contract

- outbound-only Cloudflare Tunnel и deny-by-default exposure;
- raw secrets отсутствуют в Git, argv, task, logs и evidence;
- отдельные credentials по приложению, consumer и harness profile;
- public routes только для объявленных human/service/webhook приложений;
- databases, Docker, provider/tool control и telemetry backends internal;
- wrong-profile/tool/data-access negative tests обязательны;
- Hermes рассматривается как привилегированный platform operator;
- Postgres остаётся recovery authority независимо от projection provider.

## 8. Observability

Task, execution, harness и integration events коррелируются `task_id`, `run_id`,
`profile_ref` и trace context. Acceptance проверяет metric, structured log,
trace, dashboard datasource и firing/resolved alert в Mattermost.

## 9. Критерии готовности

Релиз принят только если на одном source/release hash доказаны:

1. source release checks;
2. повторяемый `deploy --all` и финальный `verify --all`;
3. healthy selected applications и accounts/secret bindings;
4. реальные Codex, Claude Code и Pi runs через Paperclip/Daytona/9Router;
5. Kestra/GitHub PR/check terminal lifecycle и cleanup;
6. ToolHive profile isolation и declared tool policy;
7. C027/C028/C029/C036 data/content paths и cleanup;
8. Cloudflare exact exposure set;
9. observability и Mattermost alert delivery;
10. все required connections имеют fresh hash-bound evidence.

Локальные tests и container health сами по себе не являются доказательством
этого списка.
