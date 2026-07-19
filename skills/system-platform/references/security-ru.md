# Безопасность платформы и эксплуатационные инварианты

Это обязательная baseline для self-hosted deployment. Платформа исполняет
недоверенный код, управляет OAuth/API credentials и содержит привилегированные
операторские компоненты; «всё за Cloudflare» само по себе не является защитой.

## Содержание

- [Модель угроз](#модель-угроз)
- [Неподлежащие ослаблению инварианты](#неподлежащие-ослаблению-инварианты)
- [Секреты](#секреты)
- [Edge security](#edge-security)
- [Execution и tools](#execution-и-tools)
- [Hermes](#hermes)
- [Data и приложения](#data-и-приложения)
- [Проверки перед релизом](#проверки-перед-релизом)

## Модель угроз

Учитываются: обход Cloudflare через origin, захват admin UI/webhook, утечка
секретов в Git/task/log/evidence, prompt/tool injection, вредоносный MCP или
workspace, SSRF, lateral movement между приложениями, supply-chain подмена,
ошибочная публикация internal API и потеря канонических данных.

## Неподлежащие ослаблению инварианты

1. Web ingress проходит только через outbound Cloudflare Tunnel. Origin app
   ports закрыты; SSH ограничен operator keys/network policy.
2. Для текущих human и service endpoints provisioned отдельные deny-by-default
   Cloudflare Access policies. Webhook controls принадлежат integration owner и
   не создаются Cloudflare module автоматически.
3. PostgreSQL, PostgREST, Docker, Daytona, 9Router, ToolHive control и Victoria
   backends не имеют публичного hostname.
4. Секреты не хранятся в Git, Compose YAML, Paperclip task, agent instructions,
   Notion content, argv, logs или evidence.
5. Сервисы и профили получают разные credentials с минимальными scopes.
6. Harness image не содержит direct OpenAI/Anthropic subscription auth home или
   API credential. Во время run профиль получает scoped 9Router route key;
   upstream MiniMax credential остаётся root-only у оператора/9Router.
7. PostgreSQL остаётся authority; Notion и другие внешние системы не являются
   recovery source.
8. Production images и critical tooling закрепляются reviewed version/digest;
   обновление проходит source и live acceptance.

Origin firewall применяется сразу после `config audit`, до сборок Firecrawl,
Daytona и E2E. Перед изменением правил он проверяет текущий SSH client против
`MTE_OPERATOR_SSH_CIDRS`; established SSH сохраняется, а исходящий трафик
Cloudflare Tunnel не фильтруется. Стабильная root-only копия policy не зависит
от rollback release symlink, `PartOf=docker.service` восстанавливает правила
после restart Docker, а timer перепроверяет drift каждые 15 секунд.

Внешний acceptance обязан подтвердить: TCP/22 доступен, а прямые TCP-порты
80, 443, 2377, 3000, 7946 и 20241 недоступны. Дополнительно cloudflared обязан
запускать metrics только на каноническом `127.0.0.1:20241`; любое другое bind
или расхождение argv считается release blocker.

## Секреты

Единственный редактируемый source of truth — `config/platform.env` с mode
`0600`. Root-owned server `platform.env` — сгенерированная runtime-материализация,
а не второй операторский источник.
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
но не harness environment. Core release не поставляет OAuth hub: будущий
connector package обязан хранить access/refresh tokens вне среды агента и
требовать явный consent пользователя.

## Edge security

```text
Browser/service
        |
Cloudflare DNS -> Tunnel -> Access (human/service only)
        |
 outbound encrypted Tunnel
        |
127.0.0.1 origin -> application internal network
```

DNS route для declared human/service application без соответствующей Access
policy является ошибкой. UI дополнительно сохраняет собственную auth
приложения. Service tokens не переиспользуются. Current module не конфигурирует
Cloudflare WAF, rate limits или webhook route policies. Webhook owner обязан
реализовать и проверить signature либо OAuth state/PKCE, replay window и размер
payload до отдельного exposure. Notion — outbound SaaS и не получает
Cloudflare resources.

## Execution и tools

Daytona workspace считается недоверенным. Репозиторий, task input и результат
не дают права на host. В runtime разрешены только объявленные mounts, egress и
secret refs; cleanup проверяет удаление sandbox/workspace.

ToolHive workload — отдельная trust boundary. Для каждого профиля используется
свой endpoint/bearer и reviewed allow-list. Notion MCP read-only доставляется
нативно Codex/Claude и через локальный reviewed extension в Pi `0.80.7`.
Операции create/update/archive делает только `mte.notion.connector`.
Wrong-profile bearer и запрещённый прямой `tools/call` должны отрицательно
тестироваться; Pi extension не хранит endpoint или bearer в evidence/output.

Компоненты с host-level или privileged container доступом считаются частью
trusted computing base. Их нельзя выдавать обычному task agent. Для повышенной
изоляции Daytona/ToolHive workers следует выносить на отдельный execution host.

## Hermes

Hermes — operator gateway, а не обычный agent profile. Публичный режим
`unprivileged_service` запускается без sudoers-политики и с системным
hardening. Отдельный `unrestricted_host_repair` способен диагностировать и
изменять платформу и включается только явной парой canonical mode плюс
`--grant-platform-admin`. Поэтому
его messaging identity, allow-list пользователей, audit trail и credentials
критичны. В private host-repair режиме компрометация Hermes эквивалентна
компрометации платформенного оператора.
Исполняется официальный `hermes gateway run --replace`. Доступ к хосту идёт
напрямую через native terminal Hermes и его штатные approvals.

## Data и приложения

- отдельная DB/queue identity на приложение;
- RLS/scoped PostgREST role для Paperclip; отдельные роли обязательны для будущих connector packages;
- canonical revisions/hashes и payload-free provider outbox;
- Notion projection conflict разрешается в пользу PostgreSQL;
- bootstrap registration выключается после создания owner, если API продукта
  это поддерживает;
- admin UI не заменяет service account для автоматизации.

## Проверки перед релизом

1. `make release-check` и `./platform secrets audit` проходят на чистом tree.
2. `cloudflare plan` не создаёт лишних hostnames/Access policies; acceptance
   проверяет невозможность прямого origin access. Это не является проверкой WAF,
   rate limit или webhook policy, так как они не provisioned этим release.
3. Secret scan охватывает source, rendered projections и evidence.
4. Profile isolation, denied MCP calls и cross-role data access проверены
   негативными canaries.
5. Real Codex/Claude/Pi E2E использует только профильные runtime refs и завершает
   cleanup.
6. Один `run_id` находится в metrics/logs/traces; alert delivery подтверждён.
7. Все required `config/acceptance-requirements.yaml` rows имеют свежий hash-bound result.

Уязвимости следует сообщать по процедуре в [security guide](security-policy.md), не через публичный
issue с логами или credentials.
