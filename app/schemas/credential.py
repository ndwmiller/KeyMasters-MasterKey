from pydantic import BaseModel, Field


class CredentialCreate(BaseModel):
    service: str = Field(min_length=1, max_length=128)
    username: str = Field(max_length=256)
    password: str = Field(min_length=1, max_length=1024)
    notes: str | None = Field(default=None, max_length=4096)


class CredentialUpdate(BaseModel):
    service: str | None = Field(default=None, min_length=1, max_length=128)
    username: str | None = Field(default=None, max_length=256)
    password: str | None = Field(default=None, min_length=1, max_length=1024)
    notes: str | None = Field(default=None, max_length=4096)


class CredentialMeta(BaseModel):
    id: int
    service: str
    created_at: str
    updated_at: str


class CredentialFull(CredentialMeta):
    username: str
    password: str
    notes: str | None = None
