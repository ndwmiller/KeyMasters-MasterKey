from pydantic import BaseModel, Field, field_validator


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    master_password: str = Field(min_length=12, max_length=1024)

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
