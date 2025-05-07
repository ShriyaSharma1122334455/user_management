from pathlib import Path
from pydantic import Field, AnyUrl, DirectoryPath, SecretStr, validator
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # --- Application Behavior ---
    debug: bool = Field(
        default=False, 
        description="Enable debug mode (verbose logging, stack traces)"
    )
    max_login_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum allowed failed login attempts before lockout"
    )

    # --- Server Configuration ---
    server_base_url: AnyUrl = Field(
        default='http://localhost:8000',
        description="Base URL for API endpoints"
    )
    static_files_dir: DirectoryPath = Field(
        default=Path('static'),
        description="Directory for static files"
    )

    # --- Authentication ---
    jwt_secret_key: SecretStr = Field(
        default=SecretStr("change-me-in-production"),
        description="Secret for JWT token signing"
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm",
        pattern="^(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384)$"
    )
    access_token_expire_minutes: int = Field(
        default=15,
        ge=5,
        description="Access token validity in minutes"
    )
    refresh_token_expire_minutes: int = Field(
        default=1440,
        ge=60,
        description="Refresh token validity in minutes"
    )

    # --- Database ---
    database_url: SecretStr = Field(
        default=SecretStr("postgresql+asyncpg://user:password@localhost:5432/myappdb"),
        description="Full database connection URL"
    )
    
    # Alternative DB config (only use if not using database_url)
    postgres_user: Optional[str] = None
    postgres_password: Optional[SecretStr] = None
    postgres_server: Optional[str] = None
    postgres_port: Optional[int] = None
    postgres_db: Optional[str] = None

    # --- Third Party Integrations ---
    discord_bot_token: SecretStr = Field(
        default=SecretStr("NONE"),
        description="Discord bot authentication token"
    )
    discord_channel_id: Optional[int] = Field(
        default=None,
        description="Default channel ID for bot communications"
    )
    
    openai_api_key: SecretStr = Field(
        default=SecretStr("NONE"),
        description="OpenAI API key"
    )

    # --- Email Configuration ---
    email_enabled: bool = Field(
        default=False,
        description="Enable/disable email functionality"
    )
    email_from: str = Field(
        default="noreply@example.com",
        description="Default sender email address"
    )
    smtp_server: str = Field(
        default="sandbox.smtp.mailtrap.io",
        description="SMTP server hostname"
    )
    smtp_port: int = Field(
        default=587,
        ge=1,
        le=65535,
        description="SMTP server port"
    )
    smtp_username: SecretStr = Field(
        default=SecretStr(""),
        description="SMTP authentication username"
    )
    smtp_password: SecretStr = Field(
        default=SecretStr(""),
        description="SMTP authentication password"
    )
    email_test_mode: bool = Field(
        default=True,
        description="When enabled, emails are printed to console instead of sending"
    )

    # --- Admin Account ---
    admin_auto_create: bool = Field(
        default=False,
        description="Automatically create admin account if missing"
    )
    admin_email: EmailStr = Field(
        default="admin@example.com",
        description="Default admin account email"
    )
    admin_password: SecretStr = Field(
        default=SecretStr("ChangeThisPassword!"),
        min_length=12,
        description="Temporary admin password (change after first login)"
    )

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'
        env_prefix = 'APP_'  # e.g. APP_DATABASE_URL
        case_sensitive = False

    @validator('database_url', pre=True)
    def assemble_db_url(cls, v, values):
        if v and v != "postgresql+asyncpg://user:password@localhost:5432/myappdb":
            return v
            
        if all(values.get(f) for f in ['postgres_user', 'postgres_password', 
                                      'postgres_server', 'postgres_db']):
            return (
                f"postgresql+asyncpg://{values['postgres_user']}:"
                f"{values['postgres_password'].get_secret_value()}@"
                f"{values['postgres_server']}:{values.get('postgres_port', 5432)}/"
                f"{values['postgres_db']}"
            )
        return v

settings = Settings()