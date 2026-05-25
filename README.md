# Odoo Ticket Fetcher

Read-only tool for exporting Odoo project tasks to local Markdown files.

## Features

- Exports tasks with metadata, descriptions, and attachments
- Fetch by task ID, tags (AND/OR logic), project, or archived status
- Converts HTML descriptions to Markdown
- Extracts embedded images from descriptions (saved to files or embedded as base64 data URIs)
- Downloads task attachments via RPC
- Config file support for credentials
- Enforced read-only operations (method whitelist)

## Requirements

- Python 3.10+
- Odoo 10-19 (XML-RPC deprecated in Odoo 20)
- No external dependencies (stdlib only)

## Installation

```bash
git clone https://github.com/yourusername/odoo-ticket-fetcher.git
cd odoo-ticket-fetcher
```

## Usage

```bash
# Fetch specific tasks by ID
python odoo_ticket_fetcher.py --ids 12345 67890

# Filter by tags (AND - must have both)
python odoo_ticket_fetcher.py --tags "Bug" "qweb"

# Filter by tags (OR - must have any)
python odoo_ticket_fetcher.py --tags-any "Bug" "Feature"

# Filter by project
python odoo_ticket_fetcher.py --project "Support"

# Include archived tasks
python odoo_ticket_fetcher.py --project "Support" --include-archived

# Fetch all tasks with limit
python odoo_ticket_fetcher.py --all --limit 100

# Embed description images directly in the Markdown (self-contained)
python odoo_ticket_fetcher.py --ids 12345 --embed-images

# Dry run (preview without downloading)
python odoo_ticket_fetcher.py --tags "Bug" --dry-run
```

## Configuration

Create `~/.config/odoo_tickets.toml`:

```toml
[default]
url = "https://odoo.example.com"
db = "production"
username = "user@example.com"
password = "your-password-or-api-key"
```

Set secure permissions:
```bash
chmod 600 ~/.config/odoo_tickets.toml
```

Or pass credentials via CLI args / interactive prompts.

## Output Structure

```
odoo_tickets/
├── 12345/
│   ├── task.md
│   └── files/
│       ├── embedded_1.png    # (omitted with --embed-images)
│       └── document.pdf
└── 12346/
    └── ...
```

With `--embed-images`, description images are base64-encoded directly into `task.md`
instead of saved as separate files. Task-level attachments still go to `files/`.

## License

MIT
