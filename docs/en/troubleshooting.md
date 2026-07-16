# Troubleshooting

Diagnose from the narrowest read-only command and retain the run/release/source
hash. Do not edit rendered files or paste secret-bearing output.

```bash
./platform status
./platform config audit
./platform config diff
./platform verify --all
./platform connections check
```

| Plane | Diagnostics |
|---|---|
| Paperclip | `./platform runtime paperclip status` and `verify` |
| Environments/secrets | `paperclip-environments status`, `paperclip-secrets status` |
| Daytona | `./platform daytona status` and `verify` |
| Harness routing | `./platform harness-auth status` and `verify` |
| ToolHive | `./platform tools status` and `verify` |
| Provisioning | `./platform provision status` and `verify` |
| Notion projection | `./platform notion-projection status` and `verify` |
| Kestra | `kestra-control status`, `kestra-canary status` |
| Integrations | `./platform integration-canaries status` |
| Hermes | `./platform hermes status` and `health` |
| Edge | `./platform cloudflare plan`, `status`, `acceptance` |

## Rules

1. A configuration mismatch is fixed in the canonical input, then rendered;
   never patch a projection in place.
2. A failed live check is not converted to `passed` because the container is
   healthy.
3. Use `--resume` only for the same source and activation state. Otherwise
   start a new full deployment.
4. Redact values; fingerprints, IDs and hashes are sufficient for evidence.
5. Preserve failed provider/workspace state until the owning cleanup or
   investigation has completed.

If a component cannot be diagnosed with its status/verify command, treat that
as an observability defect and add a fail-closed check before relaxing the gate.
