# Спецификация и критерии готовности платформы

## Содержание

- [1. Назначение](#1-назначение)
- [2. Ответственность компонентов](#2-ответственность-компонентов)
- [3. Агентские профили](#3-агентские-профили)
- [4. Task/run lifecycle](#4-taskrun-lifecycle)
- [5. Data/content contract](#5-datacontent-contract)
- [6. Конфигурация и deployment](#6-конфигурация-и-deployment)
- [7. Security contract](#7-security-contract)
- [8. Observability](#8-observability)
- [9. Критерии готовности](#9-критерии-готовности)

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
| Automation/OAuth connectors | Extension contract; implementation not shipped |
| Search/crawl | SearXNG, Firecrawl |
| Operator gateway | Hermes |
| Communication/alerts | Mattermost; optional Telegram |
| Canonical data/documents | PostgreSQL + scoped PostgREST |
| Tables/documents projection | Notion connector |
| Deployment | Bash index + Docker Compose; Terraform только для Cloudflare |
| Edge | Cloudflare Tunnel/Access |
| Telemetry | OTel, Victoria*, Grafana, Alertmanager |

## 3. Агентские профили

Декларативный каталог `config/profiles/catalog.yaml` поставляет три профиля:

- `coding-daytona-codex`;
- `coding-daytona-claude`;
- `coding-daytona-pi`.

Профиль задаёт harness/adapter, Daytona environment/workspace mode, instructions
и skills, resource limits, runtime packages, 9Router secret ref, ToolHive
endpoint/bearer, MCP policy и auth policy. Образ не содержит direct
OpenAI/Anthropic subscription auth home или API credential: во время run профиль
получает scoped 9Router route key, а upstream MiniMax credential остаётся
root-only у оператора/9Router.

В текущем source Codex получает Context7 и профильный ToolHive через точные
adapter args, Claude Code — через managed MCP config. Pi `0.80.7` получает
Context7 через официальный `@upstash/context7-pi`, а профильный ToolHive — через
committed local extension с нативными Pi tools `toolhive_list_tools` и
`toolhive_call`. Их live-статус подтверждает только свежий release-bound
acceptance receipt для выбранного Daytona artifact и активного release.

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

Текущая реализация использует native Paperclip API: Kestra создаёт Issue через
`POST /api/companies/{company_id}/issues`, затем читает Issue, runs, documents
и diagnostics по его native ID. Старый нормализованный `/v1/runs` остался
только историческим прототипным контрактом и не является runtime gateway.

## 5. Data/content contract

Активный профиль — `postgres-notion`.

- PostgreSQL владеет canonical records/documents, ID, revision, hash и payload.
- PostgREST предоставляет scoped API разным consumers.
- Notion показывает таблицы и документы, но не становится источником истины.
- Leased outbox consumer выполняет idempotent projection и read-back checks.
- Platform services пишут canonical data через scoped PostgREST identities;
  coding harnesses пока не получают PostgREST URL/token в runtime allowlist.
  Notion write принадлежит только connector identity, а agent read policy
  реализуется через профильные ToolHive bundles: native MCP wiring есть в source
  для Codex/Claude, а Pi использует минимальный reviewed extension и остаётся
  fail-closed при drift endpoint/bearer/profile binding.

Другие проекции данных поставляются как отдельные connector-пакеты. Их
включение требует завершённого контракта, приемлемой лицензии и полного
acceptance; в public core нет скрытых dormant applications.

## 6. Конфигурация и deployment

Единственный редактируемый source of truth — `config/platform.env`. Repository
хранит его schema/example, Compose, profiles, workflows и Cloudflare declarations.
Генерируемые значения дописываются в root-owned server runtime env, который
не редактируется как отдельный источник.

Поддерживаемая последовательность:

```bash
./test.sh quick
./install.sh
```

`install.sh` явно выполняет шесть этапов: preflight, host, compose, provision,
cloudflare и verify. Каждый этап можно вызвать отдельно. Compose и API
provisioners идемпотентны; собственного snapshot/resume engine нет.

## 7. Security contract

- outbound-only Cloudflare Tunnel и deny-by-default exposure;
- raw secrets отсутствуют в Git, argv, task, logs и evidence;
- отдельные credentials по приложению, consumer и harness profile;
- public Cloudflare routes только для объявленных human/service приложений;
  webhook controls не provisioned этим release и требуют отдельного owner contract;
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
2. повторяемый `./install.sh` и финальный `./install.sh verify`;
3. healthy selected applications и accounts/secret bindings;
4. реальные Codex, Claude Code и Pi runs через Paperclip/Daytona/9Router;
5. Kestra/GitHub PR/check terminal lifecycle и cleanup;
6. ToolHive profile isolation и declared tool policy;
7. C027/C029/C036 data/content paths и cleanup;
8. Cloudflare exact exposure set;
9. observability и Mattermost alert delivery;
10. все required acceptance requirements имеют свежие release-bound receipts,
    привязанные к source/release hash.

Локальные tests и container health сами по себе не являются доказательством
этого списка.
