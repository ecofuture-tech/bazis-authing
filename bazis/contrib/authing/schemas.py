from uuid import UUID

from pydantic import BaseModel


class AuthResponse(BaseModel):
    user_id: UUID | int
    username: str
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    token: str
    logout_actions: list[dict] | None = None
