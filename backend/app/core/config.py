from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    APP_NAME: str = 'HomeOps Control Center'
    API_V1_STR: str = '/api/v1'
    DEBUG: bool = True

    SECRET_KEY: str = 'change-me-in-production'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    DB_HOST: str = 'db'
    DB_PORT: int = 3306
    DB_USER: str = 'homeops'
    DB_PASSWORD: str = 'homeops'
    DB_NAME: str = 'homeops'

    CORS_ORIGINS: str = 'http://localhost:3000'


settings = Settings()
