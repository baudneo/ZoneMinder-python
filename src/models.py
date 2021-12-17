from pydantic import BaseModel


class DBOptions(BaseModel):
    conf_path: str = None
    host: str = None
    port: int = None
    user: str = None
    password: str = None
    db_name: str = None
    db_driver: str = None
    extras: dict = {}


class APIOptions(BaseModel):
    sanitize: bool = False
    host: str = None
    basic_auth: bool = None
    port: int = None
    user: str = None
    password: str = None
    strict_ssl: bool = None
    api_url: str = None
    portal_url: str = None
    extras: dict = {}
