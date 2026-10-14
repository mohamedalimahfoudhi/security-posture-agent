# AI-TIP database handoff

The supported and reproducible database setup is:

```powershell
python backend/scripts/setup_database.py
```

Before running it, copy `backend/.env.example` to `backend/.env` and set the
database connection values, especially `DB_PASSWORD`. PostgreSQL 14 or newer
must be running, but `psql` and `createdb` do not need to be installed or on
`PATH`.

The command creates the configured database only when it does not exist. It
loads the reviewed schema, seeds labelled development data, aligns sequences,
and validates key foreign-key relationships and records.

For an explicit destructive reset of a local development database:

```powershell
python backend/scripts/setup_database.py --reset --yes
```

## Database artifacts

- `ai_tip_schema.sql` is the authoritative schema snapshot used by the setup
  command.
- `ai_tip_dump.sql` is retained as a historical/reference export. Do not use it
  for a fresh handoff installation: it predates the architecture tables needed
  by the current application and contains source-instance ownership metadata.

## Demo credentials

The initializer creates local development users only:

| Email | Password | Role |
|---|---|---|
| `admin@example.com` | `admin` | Admin |
| `analyst@example.com` | `Analyst123!` | Analyst |
| `viewer@example.com` | `Viewer123!` | Viewer |

These credentials and all seeded records are demo-only and must never be used
in production.
