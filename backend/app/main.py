from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError
from uuid import uuid4

from app.api.admin_routes import router as admin_router
from app.api.audit_routes import router as audit_router
from app.api.auth_routes import router as auth_router
from app.api.routes import router as api_router
from app.core.config import get_settings
from app.db.session import SessionLocal
from app.services.auth import bootstrap_admin_user


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Triagent", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list() or ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def attach_request_context(request, call_next):
        request_id = request.headers.get("x-request-id") or str(uuid4())
        correlation_id = request.headers.get("x-correlation-id")
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response

    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(audit_router)
    app.include_router(api_router)

    @app.on_event("startup")
    def startup_bootstrap_admin() -> None:
        db = SessionLocal()
        try:
            bootstrap_admin_user(db, settings)
        except SQLAlchemyError:
            db.rollback()
        finally:
            db.close()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
