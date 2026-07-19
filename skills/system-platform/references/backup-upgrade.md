# Backup, restore, upgrade, and rollback

The public recovery surface deliberately covers only logical backups of the
platform's ordinary Compose PostgreSQL services. It is useful for a first
release, but it is not a complete disaster-recovery system.

## Capability status

| Capability | Status | Exact boundary |
| --- | --- | --- |
| Compose PostgreSQL logical backup | **Implemented; live proof pending** | `./install.sh backup BACKUP_ID` uses `pg_dump --format=custom` for shared, Kestra, Mattermost, Firecrawl, and Daytona PostgreSQL |
| Compose PostgreSQL logical restore | **Implemented; destructive and live proof pending** | `./install.sh restore BACKUP_ID --confirm-restore` verifies every checksum and required dump before stopping clients, recreating databases, and using `pg_restore` |
| Backup replay | **Implemented** | Reusing a backup ID validates and returns the existing immutable set; a partial or corrupt set fails closed |
| Volume inventory | **Implemented** | The backup records sorted `mte-*` volume names and checksums that inventory |
| Non-database and Paperclip-native volume payload backup/restore | **Unsupported** | Volumes are preserved but their payloads, including Paperclip embedded PostgreSQL, are not captured or restored |
| Host-local container decommission | **Implemented; destructive and live proof pending** | `./install.sh decommission --confirm-decommission` removes aggregate, Daytona, and Paperclip containers without `--volumes` |
| Off-host target, encryption, or automatic rotation | **Unsupported** | Backup sets remain root-readable at `/var/backups/mte-platform`; each set records the 30-day retention policy, but pruning is manual-only and the scripts never delete an existing set |
| PostgreSQL PITR or HA | **Unsupported** | Restore has a verified pre-restore logical rollback, but no WAL archive, timeline, restore point, replication, or generic downgrade engine exists |
| Cloudflare/resource/credential retirement | **Unsupported** | Decommission leaves external resources and credentials unchanged |

Do not describe a host-local dump, retained named volume, provider snapshot,
source archive, Notion projection, or successful restart as disaster-recovery
proof.

## Backup

Choose a non-secret ID that can safely be used as a directory name:

```bash
./install.sh backup pre-upgrade-2026-07-20
```

The stage requires all five PostgreSQL containers to be running. It writes into
a private temporary directory, creates custom-format dumps without putting
passwords in arguments or logs, records exact raw and rendered Compose identity
and the current `mte-*` volume-name inventory, generates `SHA256SUMS`, and
atomically renames the completed directory. Before the first dump it stops all
running database clients in both Compose projects; they remain stopped through
the last archive validation, giving the five sequential dumps one bounded
recovery cut. An exit trap restarts exactly the clients that were running even
if a dump fails. A global recovery lock rejects concurrent backup or restore.
Replaying a completed ID validates its checksums and performs no new dump.

The destination is fixed at `/var/backups/mte-platform/BACKUP_ID`. The stage
requires twice the reported database size plus 1 GiB free before quiescing
clients. Each set records `retention_days=30` and `prune_policy=manual_only`;
expiration is advisory, and no backup is ever deleted automatically. Flags such
as `--target`, `--off-host`, or `--pitr` are not supported. The operator must
arrange any encrypted off-host copy, access control, manual pruning, monitoring,
and restore-key custody outside this MVP without placing payloads in Git or
acceptance evidence.

## Restore

Restore is deliberately explicit:

```bash
./install.sh restore pre-upgrade-2026-07-20 --confirm-restore
```

Before mutation the stage verifies the format and checksum manifest, runs
`pg_restore --list` for all five archives, requires exact raw and rendered
Compose identity, proves database connectivity, and requires the PostgreSQL
server, `pg_dump`, and `pg_restore` majors to match. It also requires twice the
current database size plus 1 GiB free for rollback. It then stops exactly the
running application clients and creates checksum- and archive-verified logical
rollback dumps before recreating any database.

If any restore or post-restore connectivity check fails after mutation begins,
the exit trap restores all five pre-restore dumps before restarting the captured
client set. A failed rollback remains a failed operation and preserves its
verified dumps for diagnosis; it is never reported as success. Non-database
volumes are never changed. After success, run fresh live acceptance:

```bash
./test.sh smoke
./install.sh verify
```

No live restore has yet been performed by the release work that introduced
this surface. Until an isolated-host restore and semantic data checks pass,
classify the implementation as source-verified only.

## Volume handling

The checksum-bound `volume-inventory.txt` is an inventory, not a backup. The
commands never archive, attach, overwrite, or delete named-volume payloads.
That means Paperclip native state, Kestra file storage, Mattermost files,
queues/caches, Daytona object/registry/runner state, ToolHive state, 9Router,
SearXNG, and observability data are outside restore coverage.

An upgrade that can mutate any excluded authority remains blocked until an
operator-specific, independently tested recovery procedure with a proven backup
covers it. Do not
invent a generic volume tar restore: application consistency, ownership, image
compatibility, and restore order differ across those stores.

## Decommission

```bash
./install.sh decommission --confirm-decommission
```

The stage preflights the canonical Compose and existing Paperclip/Daytona
remove scripts, then removes containers. It intentionally omits `--volumes` and
preserves `/var/backups/mte-platform`. Replaying it is safe: missing containers
remain absent and retained data remains untouched.

This does not remove Cloudflare DNS/Tunnel/Access, host packages, named
volumes, secret files, backup sets, or provider credentials. Final disposal
requires a separately approved inventory, retention decision, credential
revocation, external-resource removal, and explicit authorization to delete
durable data.

## Upgrade and rollback

Normal releases remain health-gated roll-forward through:

```text
preflight → host → compose → provision → cloudflare → verify
```

There is no automatic data or image rollback and no safe generic downgrade
after schema mutation. Before a risky upgrade, create a logical backup, account
for every excluded durable authority, and prove the required recovery path on
an isolated target. Correct a failed declarative stage and rerun it; never claim
that swapping source files reverses data, queues, objects, or external APIs.
