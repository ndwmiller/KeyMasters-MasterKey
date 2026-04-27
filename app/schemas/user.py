# pydantic models for user registration and login
# these enforce input rules like minimum password length before any business logic runs

from pydantic import BaseModel, Field, field_validator


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    master_password: str = Field(min_length=12, max_length=1024)  # 12 chars is the minimum we enforce

    @field_validator("username", mode="before")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip() if isinstance(v, str) else v


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    master_password: str = Field(min_length=1)


class UserOut(BaseModel):
    id: int
    username: str
