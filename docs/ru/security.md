# Безопасность платформы

Это обязательная baseline для self-hosted deployment. Платформа исполняет
недоверенный код, управляет OAuth/API credentials и содержит привилегированные
операторские компоненты; «всё за Cloudflare» само по себе не является защитой.

## Модель угроз

Учитываются: обход Cloudflare через origin, захват admin UI/webhook, утечка
секретов в Git/task/log/evidence, prompt/tool injection, вредоносный MCP или
workspace, SSRF, lateral movement между приложениями, supply-chain подмена,
ошибочная публикация internal API и потеря канонических данных.

## Неподлежащие ослаблению инварианты

1. Web ingress проходит только через outbound Cloudflare Tunnel. Origin app
   ports закрыты; SSH ограничен operator keys/network policy.
2. Human, service и webhook endpoints имеют разные deny-by-default policies.
3. PostgreSQL, PostgREST, Docker, Daytona, 9Router, ToolHive control и Victoria
   backends не имеют публичного hostname.
4. Секреты не хранятся в Git, Compose YAML, Paperclip task, agent instructions,
   Notion content, argv, logs или evidence.
5. Сервисы и профили получают разные credentials с минимальными scopes.
6. Harness image не содержит subscription auth home или persistent secret.
7. PostgreSQL остаётся authority; Notion и другие внешние системы не являются
   recovery source.
8. Production images и critical tooling закрепляются reviewed version/digest;
   обновление проходит source и live acceptance.

## Секреты

Единственный live-источник — root-owned canonical `platform.env` с mode `0600`.
Файлы сервисов, Paperclip secret refs, harness env, ToolHive runtime secrets и
Cloudflare/OpenTofu inputs являются минимальными projections. Репозиторий
содержит только schema/examples без значений.

```bash
./platform secrets init
./platform config render
./platform config audit
./platform secrets audit
```

Инициализация fill-only: повторный deploy не меняет существующий secret.
Ротация считается отдельной операцией и не симулируется ручным редактированием
rendered file. Вывод показывает только имя/fingerprint, никогда value.

Harness profiles получают отдельные 9Router keys и ToolHive bearers через
Paperclip secret references. Notion token доступен connector/ToolHive workload,
но не harness environment. OAuth connections создаются Activepieces и требуют
явного consent пользователя; access/refresh tokens не возвращаются агенту.

## Edge security

```text
Browser/service/webhook
        |
Cloudflare DNS -> WAF/rate limit -> Access/Service Auth/exact webhook policy
        |
 outbound encrypted Tunnel
        |
127.0.0.1 origin -> application internal network
```

DNS route без соответствующей policy является ошибкой. UI дополнительно
сохраняет собственную auth приложения. Service tokens не переиспользуются.
Webhook обязан проверять подпись либо OAuth state/PKCE, replay window и размер
payload. Notion — outbound SaaS и не получает Cloudflare resources.

## Execution и tools

Daytona workspace считается недоверенным. Репозиторий, task input и результат
не дают права на host. В runtime разрешены только объявленные mounts, egress и
secret refs; cleanup проверяет удаление sandbox/workspace.

ToolHive workload — отдельная trust boundary. Для каждого профиля используется
свой endpoint/bearer и reviewed allow-list. Agent Notion MCP read-only;
create/update/archive делает только `mte.notion.connector`. Wrong-profile bearer
и запрещённый прямой `tools/call` должны отрицательно тестироваться.

Компоненты с host-level или privileged container доступом считаются частью
trusted computing base. Их нельзя выдавать обычному task agent. Для повышенной
изоляции Daytona/ToolHive workers следует выносить на отдельный execution host.

## Hermes

Hermes — привилегированный operator gateway, а не обычный agent profile. В
текущем полном режиме он способен диагностировать и изменять платформу. Поэтому
его messaging identity, allow-list пользователей, audit trail и credentials
критичны; public deployment должен включать unrestricted host-operator mode
явно. Компрометация Hermes эквивалентна компрометации платформенного оператора.
Исполняется официальный `hermes gateway run --replace`. Доступ к хосту идёт
напрямую через native terminal Hermes и его штатные approvals.

## Data и приложения

- отдельная DB/queue identity на приложение;
- RLS/scoped PostgREST roles для Paperclip и Activepieces;
- canonical revisions/hashes и payload-free provider outbox;
- Notion projection conflict разрешается в пользу PostgreSQL;
- bootstrap registration выключается после создания owner, если API продукта
  это поддерживает;
- admin UI не заменяет service account для автоматизации.

## Проверки перед релизом

1. `make release-check` и `./platform secrets audit` проходят на чистом tree.
2. `cloudflare plan` не создаёт лишних hostnames/policies; acceptance проверяет
   невозможность прямого origin access.
3. Secret scan охватывает source, rendered projections и evidence.
4. Profile isolation, denied MCP calls и cross-role data access проверены
   негативными canaries.
5. Real Codex/Claude/Pi E2E использует только профильные runtime refs и завершает
   cleanup.
6. Один `run_id` находится в metrics/logs/traces; alert delivery подтверждён.
7. Все required `config/connections.yaml` rows имеют свежий hash-bound result.

Уязвимости следует сообщать по процедуре в [security guide](../en/security.md), не через публичный
issue с логами или credentials.
