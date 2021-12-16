from pydantic import BaseModel


class DBOptions(BaseModel):
    conf_path: str = None
    host: str = None
    port: int = None
    user: str = None
    password: str = None
    db_name: str = None
    db_driver: str = None


class APIOptions(BaseModel):
    port: int
    user: str
    password: str
    strict_ssl: bool
    api_url: str
    portal_url: str
