# pydantic models for user registration and login
# these enforce input rules like minimum password length before any business logic runs

from pydantic import BaseModel, Field, field_validator


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    # min 12 chars, must contain upper, lower, and a symbol
    master_password: str = Field(min_length=12, max_length=1024)

    @field_validator("username", mode="before")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip() if isinstance(v, str) else v

    @field_validator("master_password")
    @classmethod
    def _password_complexity(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("must contain at least one lowercase letter")
        if not any(c in "!@#$%^&*()-_=+[]{};:,.<>/?" for c in v):
            raise ValueError("must contain at least one symbol")
        return v


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    master_password: str = Field(min_length=1)


class UserOut(BaseModel):
    id: int
    username: str
