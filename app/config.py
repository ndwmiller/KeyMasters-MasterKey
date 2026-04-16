from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    jwt_secret: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = 15
    bcrypt_cost: int = 12
    db_path: str = "./master_key.sqlite"
    session_ttl_minutes: int = 15


def get_settings() -> Settings:
    return Settings()
