# Архитектура развёртывания

Этот документ объясняет устройство релиза. Точная последовательность задаётся
`FULL_DEPLOY_STEPS` в `tools/platform-cli/platform.py`, состав компонентов —
`config/platform.yaml`, версии — `config/platform.lock.yaml`.

## Единая точка входа

```bash
./platform plan --all
./platform preflight
./platform deploy --all
./platform status
./platform verify --all
./platform connections check
```

`deploy --all` — индексная операция из 39 шагов. Шаги вызываются
последовательно, но большинство подсистем также имеет отдельные команды
`apply/status/verify`. Несуществующих команд `backup`, `restore`, `upgrade`,
`logs` и ручного `rollback` CLI не обещает.

## Нумерованные host-runtime шаги

В `deployment/steps` находится ровно пять идемпотентных установщиков:

```text
10-host.sh
50-paperclip.sh
60-daytona.sh
90-cloudflare-tunnel.sh
91-origin-firewall.sh
```

CLI включает их в immutable release как `/opt/mte-platform/steps/*.sh` и
вызывает в нужных фазах. Это не патчи исходников: исторические миграции уже
поглощены конечными файлами и тестами. Compose и конфигурация приложений
остаются рядом с владельцами в `deployment/services/<service>`.

## Слои

```text
Operator CLI
  |
  +-- SSH transport + immutable source release
  |
  +-- canonical root-owned platform.env
  |       +-- rendered service/profile/tool projections
  |
  +-- Dokploy
  |       +-- independent application and data lifecycles
  |
  +-- host runtimes
  |       +-- Paperclip, Daytona provider, Hermes, cloudflared
  |
  +-- provisioning/reconciliation
  |       +-- users, tokens, profiles, workflows, tool bundles
  |
  +-- acceptance
          +-- live canaries, connections, evidence, final verifier
```

Долгоживущие сервисы остаются отдельными Dokploy applications. Их базы и
очереди не объединяются в одну общую lifecycle-единицу. Это позволяет
обновлять приложение без неявного удаления данных и диагностировать каждый
компонент отдельно.

## Control plane

- Kestra создаёт процесс из schedule/API/operator event и владеет ветвлением,
  retry и approval.
- Paperclip создаёт Issue/run, назначает профиль и хранит heartbeat/status.
- Hermes даёт операторский вход из мессенджеров и умеет диагностировать
  платформу через её реальные API/CLI.
- Mattermost принимает обсуждения, уведомления и alerts.

Исходники workflow принадлежат только `workflows/kestra/*.yaml`. Kestra Compose
монтирует `application.yaml`, но не каталог workflow и не включает
`--flow-path`. На deploy `server-kestra-reconcile.py provision` создаёт или
обновляет workflow через Kestra REST API, затем обязательный второй проход
доказывает no-op. Ручной импорт через UI и startup-import не поддерживаются:
они создали бы второй конкурирующий lifecycle.

## Execution plane

Paperclip выбирает один из профилей `coding-daytona-codex`,
`coding-daytona-claude`, `coding-daytona-pi`. Daytona создаёт изолированный
workspace и custom environment; harness, репозиторий и временные credentials
живут внутри runtime boundary. Harness использует собственный ключ 9Router и
свой ToolHive vMCP endpoint. После E2E verifier проверяет остановку и очистку
sandbox/workspace, ветки и pull request.

## Data/content plane

PostgreSQL — единственный источник истины. PostgREST даёт разные scoped
identities Paperclip и Activepieces. Notion — внешняя проекция таблиц и
документов; provider outbox переносит изменения с lease/`SKIP LOCKED`, проверяет
revision/hash/read-back и выполняет cleanup canary.

NocoDB/NocoDocs и Baserow/Wiki.js не разворачиваются активным профилем. Это
неактивные реализации того же connector contract, которые можно завершить и
включить отдельным осознанным релизом.

## Edge и сеть

Публичного bind на origin нет. Cloudflare Tunnel создаёт только исходящее
соединение, DNS/Access/Service Auth строятся из деклараций exposure. Человеческие
UI защищены Cloudflare Access и собственной auth приложения; service/webhook
routes имеют отдельную policy. PostgreSQL, PostgREST, ToolHive control plane,
9Router, Daytona и Victoria backends публичных hostnames не получают.

## Observability

OpenTelemetry принимает коррелированные telemetry-события. VictoriaMetrics,
VictoriaLogs и VictoriaTraces хранят соответствующие сигналы; Grafana служит UI;
vmalert/Alertmanager доставляют alerts в Mattermost. Acceptance требует найти
один canary `run_id` в метриках, логах и traces, а не только проверить health
контейнеров.

## Транзакция и evidence

Полный deploy имеет `run_id`, `release_id`, `activation_id` и hash исходников.
Promotion сериализован удалённым lock. Evidence каждого шага связывается с тем
же hash. Возобновление разрешено только по ID/пути evidence исходного запуска:

```bash
./platform deploy --all --resume RUN_ID_OR_EVIDENCE
```

Изменение исходников требует нового полного запуска. Source rollback не
объявляется rollback базы или внешнего SaaS: данные сохраняются для диагностики,
пока отдельная проверенная процедура cleanup не владеет их удалением.

## Критерий готовности

Платформа готова, когда финальный `./platform verify --all` и `connections check`
проходят на том же release hash, что и live Codex/Claude/Pi E2E, GitHub checks,
profile isolation, data/content, Cloudflare, observability и cleanup evidence.
