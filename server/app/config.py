from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://fleet:fleet@localhost:5432/fleet"

    # Database schema management
    # For production: set db_auto_create_tables=false and run `alembic upgrade head` during deploy.
    db_auto_create_tables: bool = True
    db_require_migrations_up_to_date: bool = True

    # Admin endpoints
    admin_enable_migrations_endpoint: bool = False

    # Agent long-poll and online heuristics
    agent_poll_timeout_seconds: int = 25
    agent_online_grace_seconds: int = 10

    # Agent authentication (shared secret MVP)
    # If set, all /agent/* endpoints require header: X-Fleet-Agent-Token: <token>
    agent_shared_token: str | None = None

    # Ansible integration
    ansible_dir: str = "ansible"
    ansible_log_dir: str = "ansible/logs"
    ansible_store_output_max_chars: int = 20000

    # Ansible SSH defaults (used by in-app Ansible runner)
    ansible_ssh_user: str = "imre"
    ansible_private_key_file: str | None = None  # e.g. /root/.ssh/id_ed25519

    # UI auth
    ui_cookie_secure: bool = False  # set True behind HTTPS
    ui_session_days: int = 30

    # CORS (for separate-origin frontend)
    # Comma-separated list via env is supported by pydantic-settings for list fields.
    cors_allow_origins: list[str] = []  # e.g. ["https://ui.example.com"]
    cors_allow_origin_regex: str | None = None
    cors_allow_headers: list[str] = ["*"]
    cors_allow_methods: list[str] = ["*"]
    cors_allow_credentials: bool = True

    # Bootstrap UI user (only used if the user doesn't exist yet)
    # SECURITY: do NOT ship a default password; require env override on first run.
    bootstrap_username: str = "imre"
    bootstrap_password: str | None = None

    # Terminal proxy to agent (high-risk feature)
    agent_terminal_scheme: str = "ws"  # ws|wss
    agent_terminal_port: int = 18080
    agent_terminal_token: str | None = None  # must match agent-side token

    # Background metrics refresh (for fast Overview/Attention updates)
    metrics_background_refresh_seconds: int = 60  # set 0 to disable
    metrics_background_batch_limit: int = 50


settings = Settings()
