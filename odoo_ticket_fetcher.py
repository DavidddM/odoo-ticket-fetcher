#!/usr/bin/env python3
"""
Odoo Ticket Fetcher - Read-only tool for exporting project tasks from Odoo.

This script connects to an Odoo instance via XML-RPC and exports project tasks
(tickets) to local folders. Each task gets its own directory containing a
Markdown file with metadata and description, plus any embedded images and
attachments.

Security:
    This script enforces READ-ONLY operations through a method whitelist.
    Only 'search', 'read', 'search_read', 'search_count', 'fields_get', and
    'name_get' RPC methods are permitted. Any attempt to call write operations
    (create, write, unlink, etc.) will raise a RuntimeError before the RPC
    call is made.

Features:
    - Filter tasks by tag names (AND/OR logic)
    - Filter by project name or ID
    - Include or exclusively fetch archived (inactive) tasks
    - Extract embedded base64 images from task descriptions
    - Download task attachments via RPC
    - Convert HTML descriptions to Markdown
    - Dry-run mode for previewing without downloading
    - Config file support for credentials

Output Structure:
    output_dir/
    ├── 12345/
    │   ├── task.md
    │   ├── task_raw.html (optional)
    │   └── files/
    │       ├── embedded_1.png
    │       └── document.pdf
    └── 12346/
        └── ...

Usage:
    python odoo_ticket_fetcher.py --ids 12345 67890
    python odoo_ticket_fetcher.py --tags "Bug" "Urgent"
    python odoo_ticket_fetcher.py --project "Support" --include-archived
    python odoo_ticket_fetcher.py --all --limit 50
"""

import argparse
import base64
import getpass
import html
import logging
import re
import sys
import xmlrpc.client
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[import-not-found]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

VERSION = "1.0.0"

if sys.version_info < (3, 10):
    sys.exit("Error: Python 3.10 or higher is required.")

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

CONFIG_PATH = Path.home() / ".config" / "odoo_tickets.toml"

MODEL_TASK = "project.task"
MODEL_TAG = "project.tags"
MODEL_PROJECT = "project.project"
MODEL_USER = "res.users"
MODEL_ATTACHMENT = "ir.attachment"

ALLOWED_RPC_METHODS: frozenset[str] = frozenset({
    "search",
    "read",
    "search_read",
    "search_count",
    "fields_get",
    "name_get",
})

BLOCKED_RPC_METHODS: frozenset[str] = frozenset({
    "create",
    "write",
    "unlink",
    "copy",
    "action_archive",
    "action_unarchive",
    "toggle_active",
    "message_post",
    "message_subscribe",
    "message_unsubscribe",
    "action_assign",
    "action_open",
    "action_done",
})

# Pre-compiled regex patterns for HTML to Markdown conversion
HTML_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"<br\s*/?>", re.IGNORECASE), "\n"),
    (re.compile(r"<p[^>]*>", re.IGNORECASE), "\n"),
    (re.compile(r"</p>", re.IGNORECASE), "\n"),
    (re.compile(r"<strong[^>]*>(.*?)</strong>", re.IGNORECASE | re.DOTALL), r"**\1**"),
    (re.compile(r"<b[^>]*>(.*?)</b>", re.IGNORECASE | re.DOTALL), r"**\1**"),
    (re.compile(r"<em[^>]*>(.*?)</em>", re.IGNORECASE | re.DOTALL), r"*\1*"),
    (re.compile(r"<i[^>]*>(.*?)</i>", re.IGNORECASE | re.DOTALL), r"*\1*"),
    (re.compile(r"<h1[^>]*>(.*?)</h1>", re.IGNORECASE | re.DOTALL), r"\n# \1\n"),
    (re.compile(r"<h2[^>]*>(.*?)</h2>", re.IGNORECASE | re.DOTALL), r"\n## \1\n"),
    (re.compile(r"<h3[^>]*>(.*?)</h3>", re.IGNORECASE | re.DOTALL), r"\n### \1\n"),
    (re.compile(r"<h[4-6][^>]*>(.*?)</h[4-6]>", re.IGNORECASE | re.DOTALL), r"\n#### \1\n"),
    (re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL), r"[\2](\1)"),
    (re.compile(r"<li[^>]*>(.*?)</li>", re.IGNORECASE | re.DOTALL), r"- \1\n"),
    (re.compile(r"</?(?:ul|ol)[^>]*>", re.IGNORECASE), "\n"),
    (re.compile(r"<code[^>]*>(.*?)</code>", re.IGNORECASE | re.DOTALL), r"`\1`"),
    (re.compile(r"<pre[^>]*>(.*?)</pre>", re.IGNORECASE | re.DOTALL), r"\n```\n\1\n```\n"),
    (re.compile(r"<[^>]+>"), ""),
]
WHITESPACE_COLLAPSE = re.compile(r"\n{3,}")

# Patterns for image extraction
BASE64_IMAGE_PATTERN = re.compile(
    r'<img[^>]+src=["\']data:image/([^;]+);base64,([^"\']+)["\'][^>]*/?>',
    re.IGNORECASE
)
ODOO_IMAGE_PATTERN = re.compile(
    r'<img[^>]+src=["\']/web/(?:image|content)/(\d+)[^"\']*["\'][^>]*/?>',
    re.IGNORECASE
)

MIME_TO_EXT: dict[str, str] = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "image/bmp": ".bmp",
    "application/pdf": ".pdf",
}

# Filename sanitization pattern
UNSAFE_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*]')
CONTROL_CHARS = re.compile(r"[\x00-\x1f]")

# Logger
log = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

def load_config(profile: str = "default") -> Optional[dict]:
    """
    Load connection configuration from TOML file.

    Args:
        profile: Name of the profile section to load.

    Returns:
        Dictionary with url, db, username, password if found, else None.
    """
    if tomllib is None:
        log.debug("TOML support not available (install tomli for Python < 3.11)")
        return None

    if not CONFIG_PATH.exists():
        return None

    if CONFIG_PATH.stat().st_mode & 0o077:
        log.warning("Config file has insecure permissions (should be chmod 600)")

    try:
        with open(CONFIG_PATH, "rb") as f:
            config = tomllib.load(f)
    except Exception as e:
        log.warning("Failed to parse config file: %s", e)
        return None
    
    if profile not in config:
        if profile != "default":
            log.warning("Profile '%s' not found in config", profile)
        return None
    
    section = config[profile]
    required = {"url", "db", "username", "password"}
    missing = required - set(section.keys())
    
    if missing:
        log.warning("Profile '%s' missing fields: %s", profile, missing)
        return None
    
    return {k: section[k] for k in required}


# -----------------------------------------------------------------------------
# Data Classes
# -----------------------------------------------------------------------------

@dataclass
class OdooConnection:
    """Holds Odoo connection parameters and authenticated state."""
    url: str
    db: str
    username: str
    password: str = field(repr=False)
    uid: Optional[int] = field(default=None, repr=False)
    
    def __post_init__(self):
        self.url = self.url.rstrip("/")


# -----------------------------------------------------------------------------
# RPC Client
# -----------------------------------------------------------------------------

class OdooReadOnlyClient:
    """
    Read-only XML-RPC client for Odoo with enforced method whitelist.
    
    All RPC calls go through execute() which blocks non-whitelisted methods.
    """
    
    def __init__(self, conn: OdooConnection):
        self.conn = conn
        self._common: Optional[xmlrpc.client.ServerProxy] = None
        self._models: Optional[xmlrpc.client.ServerProxy] = None
    
    def authenticate(self, timeout: int = 300) -> int:
        """
        Authenticate with the Odoo server.

        Returns:
            The authenticated user ID.

        Raises:
            ConnectionError: If connection or authentication fails.
        """
        use_https = self.conn.url.startswith("https://")
        transport_cls = xmlrpc.client.SafeTransport if use_https else xmlrpc.client.Transport
        transport = transport_cls()
        transport.timeout = timeout
        self._common = xmlrpc.client.ServerProxy(
            f"{self.conn.url}/xmlrpc/2/common", transport=transport
        )
        self._models = xmlrpc.client.ServerProxy(
            f"{self.conn.url}/xmlrpc/2/object", transport=transport
        )
        
        try:
            version_info = self._common.version()
            server_version = version_info.get("server_version", "unknown")
            log.info("Connected to Odoo %s", server_version)
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.conn.url}: {e}") from e
        
        uid = self._common.authenticate(
            self.conn.db,
            self.conn.username,
            self.conn.password,
            {}
        )
        
        if not uid:
            raise ConnectionError("Authentication failed. Check credentials.")
        
        self.conn.uid = uid
        log.info("Authenticated as UID %d", uid)
        return uid
    
    def execute(self, model: str, method: str, *args, **kwargs):
        """
        Execute a read-only RPC method on an Odoo model.
        
        Raises:
            RuntimeError: If method is not whitelisted.
        """
        if method not in ALLOWED_RPC_METHODS:
            if method in BLOCKED_RPC_METHODS:
                raise RuntimeError(f"BLOCKED: '{method}' is a write operation.")
            raise RuntimeError(f"BLOCKED: '{method}' not in whitelist.")
        
        return self._models.execute_kw(
            self.conn.db,
            self.conn.uid,
            self.conn.password,
            model,
            method,
            args,
            kwargs
        )
    
    def search_read(
        self,
        model: str,
        domain: Sequence[Sequence],
        fields: list[str],
        limit: Optional[int] = None,
        context: Optional[dict] = None
    ) -> list[dict]:
        """
        Combined search and read in a single RPC call.
        
        Args:
            model: Odoo model name.
            domain: Search domain.
            fields: Fields to fetch.
            limit: Max records to return.
            context: Optional context dict.
            
        Returns:
            List of record dictionaries.
        """
        kwargs = {"fields": fields}
        if limit:
            kwargs["limit"] = limit
        if context:
            kwargs["context"] = context
        
        return self.execute(model, "search_read", domain, **kwargs)


# -----------------------------------------------------------------------------
# Task Exporter
# -----------------------------------------------------------------------------

class TaskExporter:
    """
    Exports Odoo project tasks to local Markdown files.
    
    Uses batched RPC calls for efficiency:
    - Single search_read for all tasks
    - Bulk resolution of tag/user names
    - Bulk fetch of all attachments
    """
    
    def __init__(self, client: OdooReadOnlyClient):
        self.client = client
        self._tag_cache: dict[int, str] = {}
        self._user_cache: dict[int, str] = {}
    
    # -------------------------------------------------------------------------
    # Name Resolution (with caching)
    # -------------------------------------------------------------------------
    
    def _resolve_names_bulk(
        self,
        model: str,
        ids: set[int],
        cache: dict[int, str]
    ) -> None:
        """
        Fetch names for IDs not already in cache, update cache in place.
        """
        missing_ids = [i for i in ids if i not in cache]
        if not missing_ids:
            return
        
        records = self.client.search_read(
            model,
            [["id", "in", missing_ids]],
            ["id", "name"]
        )
        
        for rec in records:
            cache[rec["id"]] = rec["name"]
    
    def _prefetch_names(self, tasks: list[dict]) -> None:
        """
        Pre-fetch all tag and user names for a batch of tasks.
        """
        all_tag_ids: set[int] = set()
        all_user_ids: set[int] = set()
        
        for task in tasks:
            all_tag_ids.update(task.get("tag_ids") or [])
            all_user_ids.update(task.get("user_ids") or [])
        
        if all_tag_ids:
            log.debug("Pre-fetching %d tag names", len(all_tag_ids))
            self._resolve_names_bulk(MODEL_TAG, all_tag_ids, self._tag_cache)
        
        if all_user_ids:
            log.debug("Pre-fetching %d user names", len(all_user_ids))
            self._resolve_names_bulk(MODEL_USER, all_user_ids, self._user_cache)
    
    def _get_tag_names(self, tag_ids: list[int]) -> list[str]:
        """Get tag names from cache."""
        return [self._tag_cache.get(i, f"Tag#{i}") for i in tag_ids]
    
    def _get_user_names(self, user_ids: list[int]) -> list[str]:
        """Get user names from cache."""
        return [self._user_cache.get(i, f"User#{i}") for i in user_ids]
    
    # -------------------------------------------------------------------------
    # Tag/Project Resolution for Filtering
    # -------------------------------------------------------------------------
    
    def resolve_tag_ids(self, tag_names: list[str]) -> list[int]:
        """
        Convert tag names to Odoo IDs (exact match, case-sensitive).
        
        Returns:
            List of tag IDs, preserving input order where found.
        """
        if not tag_names:
            return []
        
        records = self.client.search_read(
            MODEL_TAG,
            [["name", "in", tag_names]],
            ["id", "name"]
        )
        
        if not records:
            log.warning("No tags found matching: %s", tag_names)
            return []
        
        name_to_id = {r["name"]: r["id"] for r in records}
        
        result = []
        found = []
        missing = []
        
        for name in tag_names:
            if name in name_to_id:
                result.append(name_to_id[name])
                found.append(name)
            else:
                missing.append(name)
        
        log.info("Resolved tags: %s → IDs %s", found, result)
        if missing:
            log.warning("Tags not found (exact match): %s", missing)
        
        return result
    
    def resolve_project_id(self, project_ref: str) -> Optional[int]:
        """
        Resolve a project name or ID to its Odoo ID.
        """
        if project_ref.isdigit():
            project_id = int(project_ref)
            records = self.client.search_read(
                MODEL_PROJECT,
                [["id", "=", project_id]],
                ["id", "name"]
            )
            if records:
                log.info("Resolved project ID %d: %s", project_id, records[0]["name"])
                return project_id
            log.warning("Project ID %d not found", project_id)
            return None
        
        records = self.client.search_read(
            MODEL_PROJECT,
            [["name", "=", project_ref]],
            ["id", "name"]
        )
        
        if not records:
            records = self.client.search_read(
                MODEL_PROJECT,
                [["name", "ilike", project_ref]],
                ["id", "name"]
            )
        
        if not records:
            log.warning("No project found matching: %s", project_ref)
            return None
        
        if len(records) > 1:
            log.warning("Multiple projects match '%s':", project_ref)
            for p in records:
                log.warning("    %d: %s", p["id"], p["name"])
            return None
        
        log.info("Resolved project: %s → ID %d", records[0]["name"], records[0]["id"])
        return records[0]["id"]
    
    # -------------------------------------------------------------------------
    # Task Fetching
    # -------------------------------------------------------------------------
    
    def fetch_tasks(
        self,
        task_ids: Optional[list[int]] = None,
        tag_ids_and: Optional[list[int]] = None,
        tag_ids_or: Optional[list[int]] = None,
        project_id: Optional[int] = None,
        include_archived: bool = False,
        archived_only: bool = False,
        limit: Optional[int] = None
    ) -> list[dict]:
        """
        Fetch tasks with filtering in a single search_read call.
        """
        domain = []
        context = {}

        if task_ids:
            domain = [["id", "in", task_ids]]
            context["active_test"] = False
            limit = None
        else:
            if tag_ids_and:
                for tag_id in tag_ids_and:
                    domain.append(["tag_ids", "in", [tag_id]])

            if tag_ids_or:
                domain.append(["tag_ids", "in", tag_ids_or])

            if project_id:
                domain.append(["project_id", "=", project_id])

            if archived_only:
                domain.append(["active", "=", False])
                context["active_test"] = False
            elif include_archived:
                context["active_test"] = False

        fields = [
            "id", "name", "active", "description", "tag_ids",
            "project_id", "stage_id", "user_ids", "date_deadline",
            "priority", "create_date", "write_date",
        ]

        tasks = self.client.search_read(
            MODEL_TASK,
            domain,
            fields,
            limit=limit,
            context=context
        )
        
        if tasks:
            log.info("Found %d task(s)", len(tasks))
        
        return tasks
    
    # -------------------------------------------------------------------------
    # Attachment Fetching (Batched)
    # -------------------------------------------------------------------------
    
    def fetch_all_attachments(self, task_ids: list[int]) -> dict[int, list[dict]]:
        """
        Fetch all attachments for multiple tasks in a single RPC call.
        
        Returns:
            Dict mapping task_id → list of attachment dicts.
        """
        if not task_ids:
            return {}
        
        records = self.client.search_read(
            MODEL_ATTACHMENT,
            [
                ["res_model", "=", MODEL_TASK],
                ["res_id", "in", task_ids],
            ],
            ["id", "name", "mimetype", "datas", "file_size", "res_id"]
        )
        
        result: dict[int, list[dict]] = {tid: [] for tid in task_ids}
        for rec in records:
            task_id = rec["res_id"]
            if task_id in result:
                result[task_id].append(rec)
        
        total = sum(len(v) for v in result.values())
        if total:
            log.info("Fetched %d attachment(s) for %d task(s)", total, len(task_ids))
        
        return result
    
    def fetch_attachment_by_id(self, attachment_id: int) -> Optional[dict]:
        """
        Fetch a single attachment by ID (for inline images in descriptions).
        """
        records = self.client.search_read(
            MODEL_ATTACHMENT,
            [["id", "=", attachment_id]],
            ["name", "mimetype", "datas"]
        )
        return records[0] if records else None
    
    # -------------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------------
    
    @staticmethod
    def sanitize_filename(name: str) -> str:
        """Remove unsafe characters from filename."""
        name = UNSAFE_FILENAME_CHARS.sub("_", name)
        name = CONTROL_CHARS.sub("", name)
        name = name.strip(". ")
        return name or "unnamed"
    
    @staticmethod
    def get_extension(mimetype: str, fallback_name: str = "") -> str:
        """Get file extension for a MIME type."""
        if mimetype in MIME_TO_EXT:
            return MIME_TO_EXT[mimetype]
        if fallback_name and "." in fallback_name:
            return "." + fallback_name.rsplit(".", 1)[-1].lower()
        return ".bin"
    
    @staticmethod
    def html_to_markdown(html_content: str) -> str:
        """Convert HTML to Markdown using pre-compiled patterns."""
        if not html_content:
            return ""
        
        text = html_content
        for pattern, replacement in HTML_PATTERNS:
            text = pattern.sub(replacement, text)
        
        text = html.unescape(text)
        text = WHITESPACE_COLLAPSE.sub("\n\n", text)
        return text.strip()
    
    # -------------------------------------------------------------------------
    # Image Extraction
    # -------------------------------------------------------------------------
    
    def extract_and_save_images(
        self,
        html_content: str,
        files_dir: Path,
        image_counter: list[int],
        embed_images: bool = False
    ) -> str:
        """
        Extract images from HTML, save to disk, return modified HTML.
        
        Args:
            html_content: Raw HTML string.
            files_dir: Directory to save images.
            image_counter: Mutable list[int] to track image numbering across calls.
            
        Returns:
            HTML with image tags replaced by Markdown image syntax.
        """
        if not html_content:
            return ""
        
        result = html_content
        
        def save_base64_image(match: re.Match) -> str:
            image_type = match.group(1).lower()
            image_data = match.group(2)

            if embed_images:
                return (
                    f"\n\n![embedded image]"
                    f"(data:image/{image_type};base64,{image_data})\n\n"
                )

            if image_type == "jpeg":
                image_type = "jpg"

            image_counter[0] += 1
            filename = f"embedded_{image_counter[0]}.{image_type}"

            try:
                files_dir.mkdir(parents=True, exist_ok=True)
                (files_dir / filename).write_bytes(
                    base64.b64decode(image_data)
                )
                log.debug("Saved embedded image: %s", filename)
                return f"\n\n![{filename}](files/{filename})\n\n"
            except Exception as e:
                log.warning("Failed to decode embedded image: %s", e)
                return match.group(0)
        
        result = BASE64_IMAGE_PATTERN.sub(save_base64_image, result)
        
        def save_odoo_attachment(match: re.Match) -> str:
            attachment_id = int(match.group(1))

            try:
                att = self.fetch_attachment_by_id(attachment_id)
                if att and att.get("datas"):
                    if embed_images:
                        mimetype = att.get("mimetype", "image/png")
                        name = att.get("name", f"image_{attachment_id}")
                        return (
                            f"\n\n![{name}]"
                            f"(data:{mimetype};base64,{att['datas']})\n\n"
                        )

                    ext = self.get_extension(
                        att.get("mimetype", ""),
                        att.get("name", ""),
                    )
                    filename = f"attachment_{attachment_id}{ext}"

                    files_dir.mkdir(parents=True, exist_ok=True)
                    (files_dir / filename).write_bytes(
                        base64.b64decode(att["datas"])
                    )

                    log.debug("Saved attachment image: %s", filename)
                    return (
                        f"\n\n![{att.get('name', filename)}]"
                        f"(files/{filename})\n\n"
                    )
            except Exception as e:
                log.warning(
                    "Failed to fetch attachment %d: %s",
                    attachment_id, e,
                )

            return match.group(0)
        
        result = ODOO_IMAGE_PATTERN.sub(save_odoo_attachment, result)
        
        return result
    
    # -------------------------------------------------------------------------
    # Export
    # -------------------------------------------------------------------------
    
    def export_task(
        self,
        task: dict,
        output_dir: Path,
        attachments: list[dict],
        keep_raw_html: bool = False,
        embed_images: bool = False
    ) -> None:
        """
        Export a single task to a folder.
        
        Args:
            task: Task record dict.
            output_dir: Parent output directory.
            attachments: Pre-fetched attachments for this task.
            keep_raw_html: Whether to save original HTML.
        """
        task_id = task["id"]
        task_name = task.get("name", "Untitled")
        is_archived = not task.get("active", True)
        
        status = " [ARCHIVED]" if is_archived else ""
        log.info("Exporting task %d: %s%s", task_id, task_name[:50], status)
        
        task_dir = output_dir / str(task_id)
        task_dir.mkdir(parents=True, exist_ok=True)
        files_dir = task_dir / "files"
        
        raw_description = task.get("description") or ""
        image_counter = [0]
        processed_description = self.extract_and_save_images(
            raw_description, files_dir, image_counter,
            embed_images=embed_images,
        )
        
        saved_files = []
        for att in attachments:
            if not att.get("datas"):
                continue
            
            original_name = att.get("name", f"attachment_{att['id']}")
            safe_name = self.sanitize_filename(original_name)
            
            if safe_name in saved_files:
                base, ext = (safe_name.rsplit(".", 1) + [""])[:2]
                safe_name = f"{base}_{att['id']}.{ext}" if ext else f"{base}_{att['id']}"
            
            try:
                files_dir.mkdir(parents=True, exist_ok=True)
                (files_dir / safe_name).write_bytes(base64.b64decode(att["datas"]))
                saved_files.append(safe_name)
                log.debug("Saved attachment: %s", safe_name)
            except Exception as e:
                log.warning("Failed to save %s: %s", original_name, e)
        
        project_name = task["project_id"][1] if task.get("project_id") else "N/A"
        stage_name = task["stage_id"][1] if task.get("stage_id") else "N/A"
        tag_names = self._get_tag_names(task.get("tag_ids") or [])
        assignee_names = self._get_user_names(task.get("user_ids") or [])
        
        md_lines = [
            f"# {task_name}",
            "",
            f"**ID:** {task_id}  ",
            f"**Active:** {task.get('active', True)}  ",
            f"**Project:** {project_name}  ",
            f"**Stage:** {stage_name}  ",
            f"**Priority:** {task.get('priority', '0')}  ",
            f"**Deadline:** {task.get('date_deadline') or 'None'}  ",
            f"**Created:** {task.get('create_date', 'N/A')}  ",
            f"**Updated:** {task.get('write_date', 'N/A')}  ",
        ]
        
        if tag_names:
            md_lines.append(f"**Tags:** {', '.join(tag_names)}  ")
        if assignee_names:
            md_lines.append(f"**Assignees:** {', '.join(assignee_names)}  ")
        
        md_lines.extend(["", "---", "", "## Description", ""])
        
        if processed_description:
            md_lines.append(self.html_to_markdown(processed_description))
        else:
            md_lines.append("*No description provided.*")
        
        if saved_files:
            md_lines.extend(["", "---", "", "## Attachments", ""])
            for fname in saved_files:
                md_lines.append(f"- [{fname}](files/{fname})")
        
        (task_dir / "task.md").write_text("\n".join(md_lines), encoding="utf-8")
        
        if keep_raw_html and raw_description:
            (task_dir / "task_raw.html").write_text(raw_description, encoding="utf-8")
    
    def export_all(
        self,
        tasks: list[dict],
        output_dir: Path,
        keep_raw_html: bool = False,
        embed_images: bool = False
    ) -> None:
        """
        Export multiple tasks with batched operations.
        
        This is the main entry point for efficient bulk export:
        1. Pre-fetch all tag/user names
        2. Fetch all attachments in one call
        3. Export each task
        """
        if not tasks:
            return
        
        log.info("Pre-fetching metadata for %d task(s)...", len(tasks))
        self._prefetch_names(tasks)
        
        task_ids = [t["id"] for t in tasks]
        attachments_by_task = self.fetch_all_attachments(task_ids)
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for i, task in enumerate(tasks, 1):
            log.info("Progress: %d/%d", i, len(tasks))
            self.export_task(
                task,
                output_dir,
                attachments_by_task.get(task["id"], []),
                keep_raw_html=keep_raw_html,
                embed_images=embed_images,
            )


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def create_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Export Odoo project tasks to Markdown (READ-ONLY)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --ids 12345 67890                        # Fetch by ID
    %(prog)s --tags "Bug" "qweb"                      # AND: must have both
    %(prog)s --tags-any "Bug" "Feature"               # OR: must have any
    %(prog)s --tags "qweb" --tags-any "bug" "Bug"     # Combined
    %(prog)s --project "Support" --include-archived
    %(prog)s --all --limit 100

Config file (~/.config/odoo_tickets.toml):
    [default]
    url = "https://odoo.example.com"
    db = "production"
    username = "me@example.com"
    password = "secret"
        """,
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    conn = parser.add_argument_group("connection")
    conn.add_argument("--url", help="Odoo URL")
    conn.add_argument("--db", help="Database name")
    conn.add_argument("--profile", default="default", metavar="NAME",
                      help="Config profile (default: default)")
    conn.add_argument("-u", "--username", help="Username")
    conn.add_argument("-p", "--password", help="Password")
    
    filt = parser.add_argument_group("filters")
    filt.add_argument("-t", "--tags", nargs="+", metavar="TAG",
                      help="Filter by tags (AND logic)")
    filt.add_argument("--tags-any", nargs="+", metavar="TAG",
                      help="Filter by tags (OR logic)")
    filt.add_argument("--project", metavar="NAME_OR_ID",
                      help="Filter by project")
    filt.add_argument("-a", "--all", action="store_true", dest="fetch_all",
                      help="Fetch all tasks")
    filt.add_argument("--include-archived", action="store_true",
                      help="Include archived tasks")
    filt.add_argument("--archived-only", action="store_true",
                      help="Only archived tasks")
    filt.add_argument("-l", "--limit", type=int, metavar="N",
                      help="Max tasks to fetch")
    filt.add_argument("--ids", nargs="+", type=int, metavar="ID",
                      help="Fetch specific task IDs (overrides other filters)")

    out = parser.add_argument_group("output")
    out.add_argument("-o", "--output", default="./odoo_tickets", metavar="DIR",
                     help="Output directory")
    out.add_argument("--raw-html", action="store_true",
                     help="Also save raw HTML")
    out.add_argument("--embed-images", action="store_true",
                     help="Embed description images as base64 data URIs "
                          "directly in the Markdown file")
    out.add_argument("--dry-run", action="store_true",
                     help="List tasks without exporting")
    
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress output except errors")
    
    return parser


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure logging based on verbosity flags."""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )


def main() -> int:
    """Main entry point. Returns exit code."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    setup_logging(args.verbose, args.quiet)
    
    if not any([args.ids, args.tags, args.tags_any, args.fetch_all, args.archived_only, args.project]):
        parser.error("Specify --ids, --tags, --tags-any, --project, --all, or --archived-only")
    
    config = load_config(args.profile)
    
    url = args.url or (config and config["url"])
    db = args.db or (config and config["db"])
    username = args.username or (config and config["username"])
    password = args.password or (config and config["password"])
    
    if not url:
        url = input("Odoo URL: ")
    if not db:
        db = input("Database: ")
    if not username:
        username = input("Username: ")
    if not password:
        password = getpass.getpass("Password: ")
    
    conn = OdooConnection(url=url, db=db, username=username, password=password)
    
    log.info("=" * 60)
    log.info("ODOO TICKET FETCHER — READ-ONLY MODE")
    if config:
        log.info("Config: %s [profile: %s]", CONFIG_PATH, args.profile)
    log.info("=" * 60)
    
    try:
        client = OdooReadOnlyClient(conn)
        client.authenticate()
        
        exporter = TaskExporter(client)

        tag_ids_and = []
        tag_ids_or = []
        project_id = None

        if args.ids:
            log.info("Fetching tasks by ID: %s", args.ids)
            if args.tags or args.tags_any or args.project:
                log.warning("--ids overrides --tags, --tags-any, and --project")
        else:
            if args.tags:
                tag_ids_and = exporter.resolve_tag_ids(args.tags)
                if not tag_ids_and:
                    log.error("No matching tags for --tags. Exiting.")
                    return 1
                log.info("  AND filter: must have ALL")

            if args.tags_any:
                tag_ids_or = exporter.resolve_tag_ids(args.tags_any)
                if not tag_ids_or:
                    log.error("No matching tags for --tags-any. Exiting.")
                    return 1
                log.info("  OR filter: must have ANY")

            if args.project:
                project_id = exporter.resolve_project_id(args.project)
                if not project_id:
                    log.error("Could not resolve project. Exiting.")
                    return 1

        log.info("Fetching tasks...")
        tasks = exporter.fetch_tasks(
            task_ids=args.ids,
            tag_ids_and=tag_ids_and or None,
            tag_ids_or=tag_ids_or or None,
            project_id=project_id,
            include_archived=args.include_archived,
            archived_only=args.archived_only,
            limit=args.limit
        )
        
        if not tasks:
            log.info("No tasks found.")
            return 0
        
        if args.dry_run:
            log.info("")
            log.info("DRY RUN — Tasks that would be exported:")
            log.info("-" * 60)
            for task in tasks:
                status = " [ARCHIVED]" if not task.get("active", True) else ""
                project = task["project_id"][1] if task.get("project_id") else "N/A"
                log.info("  %8d  %s%s", task["id"], task["name"][:45], status)
                log.info("           Project: %s", project)
            log.info("-" * 60)
            log.info("Total: %d task(s)", len(tasks))
            return 0
        
        output_dir = Path(args.output)
        exporter.export_all(
            tasks, output_dir,
            keep_raw_html=args.raw_html,
            embed_images=args.embed_images,
        )
        
        log.info("=" * 60)
        log.info("Exported %d task(s) to: %s", len(tasks), output_dir.resolve())
        log.info("=" * 60)
        return 0
        
    except ConnectionError as e:
        log.error("Connection error: %s", e)
        return 1
    except RuntimeError as e:
        log.error("Security block: %s", e)
        return 1
    except xmlrpc.client.Fault as e:
        log.error("Odoo RPC error: %s", e.faultString)
        return 1
    except KeyboardInterrupt:
        log.warning("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
