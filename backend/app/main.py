from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.db.session import create_db_and_tables, engine
from app.services.seed import seed_initial_data
from sqlmodel import Session

app = FastAPI(title=settings.APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.CORS_ORIGINS.split(',')],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.on_event('startup')
def on_startup() -> None:
    create_db_and_tables()
    with Session(engine) as session:
        seed_initial_data(session)


@app.get('/health')
def health():
    return {'status': 'ok'}


app.include_router(api_router, prefix=settings.API_V1_STR)
