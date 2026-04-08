from fastapi import APIRouter

from app.api.v1 import actions, audit, auth, dashboard, integrations, servers, users

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(servers.router)
api_router.include_router(actions.router)
api_router.include_router(audit.router)
api_router.include_router(users.router)
api_router.include_router(integrations.router)
