"""Private production inference API. Requires a verified offline release."""
import asyncio
from contextlib import asynccontextmanager
import hmac
from email.errors import MessageError
import os
from pathlib import Path
import secrets

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from .email import Email, parse_eml, indicators, MAX_BYTES, MAX_TEXT
from .release import load_release
from .intel import IntelPolicy, enrich, triage, summary

def create_app():
    @asynccontextmanager
    async def lifespan(app):
        key = os.environ.get("PHISHINTEL_API_KEY", "")
        if len(key) < 32:
            raise RuntimeError("Configure a strong API key before starting")
        app.state.key = key
        app.state.model = load_release(Path(os.environ["PHISHINTEL_MODEL"]),
                                       os.environ["PHISHINTEL_MODEL_SHA256"])
        app.state.slots = asyncio.Semaphore(4)
        policy_path = os.environ.get("PHISHINTEL_POLICY")
        app.state.policy = IntelPolicy.load(policy_path) if policy_path else IntelPolicy()
        yield

    app = FastAPI(title="PhishIntel", version="1.0.0", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/healthz")
    async def health():
        return {"status": "ok"}

    @app.get("/readyz")
    async def ready(request: Request):
        if not hasattr(request.app.state, "model"):
            raise HTTPException(503, "Not ready")
        return {"status": "ready"}

    @app.post("/v1/analyse")
    async def analyse_email(request: Request):
        token = request.headers.get("authorization", "")
        expected = "Bearer " + request.app.state.key
        if not hmac.compare_digest(token.encode(), expected.encode()):
            raise HTTPException(401, "Unauthorised", headers={"WWW-Authenticate": "Bearer"})
        if request.headers.get("content-encoding", "identity").lower() != "identity":
            raise HTTPException(415, "Compressed request bodies are unsupported")
        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type not in {"message/rfc822", "text/plain"}:
            raise HTTPException(415, "Use message/rfc822 or text/plain")
        slots = request.app.state.slots
        try:
            await asyncio.wait_for(slots.acquire(), timeout=.05)
        except TimeoutError:
            raise HTTPException(429, "Server busy", headers={"Retry-After": "1"})
        try:
            async def read_body():
                raw = bytearray()
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > MAX_BYTES:
                        raise HTTPException(413, "Request too large")
                    raw.extend(chunk)
                return bytes(raw)
            try:
                raw = await asyncio.wait_for(read_body(), timeout=10)
            except TimeoutError:
                raise HTTPException(408, "Request timed out")
            def run():
                if content_type == "message/rfc822":
                    email = parse_eml(raw)
                else:
                    body = raw.decode("utf-8", "strict")
                    if len(body) > MAX_TEXT:
                        raise ValueError("Text too long")
                    email = Email(body=body)
                result = request.app.state.model.analyse(email.model_text())
                findings = indicators(email)
                evidence = enrich(email, request.app.state.policy)
                decision = triage(result, evidence, findings)
                return {"request_id": secrets.token_hex(12),
                        "model_sha256": request.app.state.model.fingerprint,
                        "score_type": "uncalibrated_model_score",
                        **result, "indicators": findings, "evidence": evidence,
                        "triage": decision, "summary": summary(result, evidence, decision),
                        "recommendation": "review" if decision["priority"] != "routine"
                        else "verify independently"}
            try:
                return JSONResponse(await run_in_threadpool(run))
            except (ValueError, RecursionError, UnicodeError, LookupError, MessageError):
                raise HTTPException(422, "Invalid or unsupported email")
        finally:
            slots.release()
    return app

app = create_app()
