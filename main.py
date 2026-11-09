"""
FastAPI entrypoint for Vitarka — Confidential AI Security Gateway.
Provides POST /chat, GET /health, POST /v1/chat/completions, approval/admin APIs,
and Vitarka-specific endpoints: GET /attestation, GET /tee/status, GET /audit/chain/verify.
"""

import time
import os
import logging
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Header, HTTPException, Query, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import base64

from gateway.models import (
    ChatRequest,
    ChatResponse,
    FileAttachment,
    IngestRequest,
    IngestResponse,
    FindingSummary,
    OpenAIChatCompletionRequest,
    OpenAIChatCompletionResponse,
    OpenAIChoice,
    OpenAIChoiceMessage,
    OpenAIUsage,
)
from gateway.pipeline import SecurityPipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("gateway.main")

pipeline = SecurityPipeline()

# Eagerly initialize policy engine and audit logger so test client and app have them immediately
try:
    from gateway.policy import PolicyEngine
    pipeline.set_policy_engine(PolicyEngine(os.getenv("POLICIES_PATH", "policies.yaml")))
except Exception as e:
    logger.warning(f"Initial policy engine load error: {e}")

try:
    from gateway.audit import AuditLogger
    pipeline.set_audit_logger(AuditLogger())
except Exception as e:
    logger.warning(f"Initial audit logger load error: {e}")

try:
    from gateway.rag import RAGEngine
    pipeline.set_rag_engine(RAGEngine())
except Exception as e:
    logger.warning(f"Initial RAG engine load error: {e}")

try:
    from gateway.output_guard import OutputGuard
    pipeline.set_output_guard(OutputGuard(audit_logger=pipeline.audit_logger, policy_engine=pipeline.policy_engine))
except Exception as e:
    logger.warning(f"Initial OutputGuard load error: {e}")

# ── TEE / Vitarka ─────────────────────────────────────────────────────────────
from gateway.tee import get_tee_mode, TeeMode, tee_enabled
from gateway.tee.manifest import build_manifest
from gateway.tee.attestation import get_provider
from gateway.tee.key_broker import initialize_keys, get_released_keys

_tee_mode = get_tee_mode()
_manifest = build_manifest()
_tee_provider = get_provider()

_tee_status: Dict[str, Any] = {
    "mode": _tee_mode.value,
    "hardware_type": _tee_provider.hardware_type,
    "provider_name": _tee_provider.name,
    "manifest_hash": _manifest.manifest_hash,
    "keys_released": False,
    "startup_error": None,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown hooks."""
    global _tee_status
    logger.info("Initializing Vitarka Confidential AI Security Gateway...")

    if _tee_mode != TeeMode.OFF:
        try:
            import secrets as _sec
            startup_nonce = _sec.token_hex(32)
            evidence = _tee_provider.get_evidence(
                nonce=startup_nonce,
                tls_pubkey_pem="",
                manifest=_manifest,
            )
            released = initialize_keys(evidence)
            _tee_status["keys_released"] = True
            logger.info("TEE key release succeeded via %s", released.broker_name)
        except Exception as e:
            _tee_status["startup_error"] = str(e)
            if _tee_mode == TeeMode.PRODUCTION:
                raise RuntimeError(f"FATAL: TEE key release failed (fail-closed): {e}") from e
            logger.warning("TEE key release failed (non-fatal in %s): %s", _tee_mode.value, e)
    else:
        logger.info("TEE_MODE=off — TEE features inactive.")

    try:
        from gateway.audit import AuditLogger
        audit = AuditLogger()
        pipeline.set_audit_logger(audit)
        logger.info("Audit logger attached.")
    except Exception as e:
        logger.warning(f"Audit logger init failed: {e}")

    try:
        from gateway.policy import PolicyEngine
        policy_path = os.getenv("POLICIES_PATH", "policies.yaml")
        pe = PolicyEngine(policy_path)
        pipeline.set_policy_engine(pe)
        logger.info(f"Policy engine loaded from {policy_path}.")
    except Exception as e:
        logger.warning(f"Policy engine init failed: {e}")

    try:
        from gateway.rag import RAGEngine
        rag = RAGEngine()
        pipeline.set_rag_engine(rag)
        logger.info("Access-controlled RAG engine attached.")
    except Exception as e:
        logger.warning(f"RAG engine init failed: {e}")

    try:
        from gateway.output_guard import OutputGuard
        og = OutputGuard(
            audit_logger=pipeline.audit_logger,
            policy_engine=pipeline.policy_engine
        )
        pipeline.set_output_guard(og)
        logger.info("Output guard attached.")
    except Exception as e:
        logger.warning(f"Output guard init failed: {e}")

    yield

    released = get_released_keys()
    if released:
        released.zeroize()
    logger.info("Vitarka gateway shut down — key material zeroized.")


app = FastAPI(
    title="Vitarka — Confidential AI Security Gateway",
    description=(
        "Zero-trust, hardware-attested reverse-proxy guardrail between users and LLMs. "
        "Powered by AMD SEV-SNP / Intel TDX confidential computing."
    ),
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["System"])
async def health():
    """Health check: serving | degraded | refusing."""
    startup_err = _tee_status.get("startup_error")
    if startup_err and _tee_mode == TeeMode.PRODUCTION:
        svc_status = "refusing"
    elif startup_err:
        svc_status = "degraded"
    else:
        svc_status = "serving"

    return {
        "status": svc_status,
        "provider": pipeline.llm.provider,
        "version": "2.0.0",
        "tee_mode": _tee_mode.value,
        "tee_hardware": _tee_provider.hardware_type,
        "keys_released": _tee_status.get("keys_released", False),
        "manifest_hash": _manifest.manifest_hash[:16] + "…",
        "approvals_pending": len([a for a in pipeline.approval_queue.values() if a.get("status") == "pending"]),
        "policy_loaded": pipeline.policy_engine is not None,
        "rag_ready": pipeline.rag_engine is not None,
    }


@app.get("/attestation", tags=["Trust"])
async def get_attestation(nonce: str = Query(..., description="Caller-supplied random nonce (hex)")):
    """
    GET /attestation?nonce=<hex>
    Returns hardware attestation evidence bound to the nonce.
    TEE_MODE=off returns mock evidence; TEE_MODE=production requires real hardware.
    """
    if not nonce or len(nonce) < 16:
        raise HTTPException(status_code=400, detail="nonce must be at least 16 hex characters")
    try:
        evidence = _tee_provider.get_evidence(nonce=nonce, tls_pubkey_pem="", manifest=_manifest)
        return {
            "hardware_type": evidence.hardware_type,
            "provider": evidence.provider_name,
            "nonce": evidence.nonce,
            "report_data_hex": evidence.report_data_hex,
            "report_hex": evidence.report_hex,
            "cert_chain": evidence.cert_chain,
            "manifest": evidence.manifest,
            "generated_at": evidence.generated_at,
            "tee_mode": _tee_mode.value,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attestation failed: {e}")


@app.get("/attestation/verify", tags=["Trust"])
async def verify_attestation(nonce: str = Query(...)):
    """Re-generate and verify evidence for the same nonce (auditor / demo use)."""
    try:
        evidence = _tee_provider.get_evidence(nonce=nonce, manifest=_manifest)
        valid = _tee_provider.verify_evidence(evidence, nonce)
        return {"valid": valid, "hardware_type": evidence.hardware_type, "nonce": nonce}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/audit/chain/verify", tags=["Trust"])
async def verify_audit_chain():
    """Verify the integrity of the hash-chained audit log."""
    from gateway.tee.chain_audit import ChainAuditLogger
    try:
        cl = ChainAuditLogger()
        result = cl.verify_chain()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/tee/status", tags=["Trust"])
async def tee_status_endpoint():
    """Return the current TEE and key-release status."""
    return _tee_status


@app.post("/chat", response_model=ChatResponse, tags=["Gateway"])
async def chat(request: ChatRequest):
    """Primary chat endpoint — full 7-stage security pipeline."""
    try:
        response = pipeline.process(request)
        return response
    except Exception as e:
        logger.error(f"Error in chat processing: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Gateway Security Error"
        )


@app.post("/v1/chat/completions", response_model=OpenAIChatCompletionResponse, tags=["OpenAI Drop-In"])
async def openai_chat_completions(
    request: OpenAIChatCompletionRequest,
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role")
):
    """OpenAI-compatible drop-in proxy endpoint."""
    user_messages = [m.content for m in request.messages if m.role == "user"]
    if not user_messages:
        raise HTTPException(status_code=400, detail="No user message provided in messages list.")
    user_prompt = user_messages[-1]

    user_id = x_user_id or "anonymous"
    role = x_user_role or "intern"

    if request.user:
        if ":" in request.user:
            parts = request.user.split(":", 1)
            user_id = parts[0]
            role = parts[1]
        else:
            user_id = request.user

    chat_req = ChatRequest(user_id=user_id, role=role, message=user_prompt)
    result = pipeline.process(chat_req)

    return OpenAIChatCompletionResponse(
        model=request.model or "vitarka-gateway",
        choices=[
            OpenAIChoice(
                index=0,
                message=OpenAIChoiceMessage(role="assistant", content=result.answer),
                finish_reason="stop"
            )
        ],
        usage=OpenAIUsage(
            prompt_tokens=len(user_prompt.split()),
            completion_tokens=len(result.answer.split()),
            total_tokens=len(user_prompt.split()) + len(result.answer.split())
        )
    )


@app.get("/approvals", tags=["Approvals"])
async def list_approvals(status_filter: Optional[str] = Query("pending")):
    """List held requests requiring administrative approval."""
    items = list(pipeline.approval_queue.values())
    if status_filter:
        items = [i for i in items if i.get("status") == status_filter]
    return {"approvals": items}


@app.post("/approvals/{approval_id}/approve", tags=["Approvals"])
async def approve_request(approval_id: str):
    """Approve a pending held request and execute through LLM."""
    if approval_id not in pipeline.approval_queue:
        raise HTTPException(status_code=404, detail="Approval ID not found")
    item = pipeline.approval_queue[approval_id]
    if item["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"Request already {item['status']}")

    item["status"] = "approved"
    item["resolved_at"] = time.time()

    req = ChatRequest(user_id=item["user_id"], role=item["role"], message=item["message"])
    context = ""
    if pipeline.rag_engine:
        context = pipeline.rag_engine.retrieve(req.message, req.user_id, req.role, item["request_id"])
    answer = pipeline.llm.generate(req.message, context=context)
    item["answer"] = answer
    return {"status": "approved", "answer": answer}


@app.post("/approvals/{approval_id}/reject", tags=["Approvals"])
async def reject_request(approval_id: str, reason: str = "Administrative policy rejection"):
    """Reject a pending held request."""
    if approval_id not in pipeline.approval_queue:
        raise HTTPException(status_code=404, detail="Approval ID not found")
    item = pipeline.approval_queue[approval_id]
    if item["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"Request already {item['status']}")

    item["status"] = "rejected"
    item["rejection_reason"] = reason
    item["resolved_at"] = time.time()
    return {"status": "rejected", "reason": reason}


@app.get("/policies", tags=["Policies"])
async def get_policies():
    """Retrieve currently active security policy configuration."""
    if not pipeline.policy_engine:
        return {"policies": {}, "loaded": False}
    return {"policies": pipeline.policy_engine.config, "loaded": True}


@app.post("/policies/reload", tags=["Policies"])
async def reload_policies():
    """Hot-reload security policies without service restart."""
    if not pipeline.policy_engine:
        raise HTTPException(status_code=500, detail="Policy engine not loaded")
    success = pipeline.policy_engine.reload()
    return {"status": "reloaded" if success else "failed"}


@app.get("/audit/events", tags=["Audit"])
async def get_audit_events(limit: int = 50, category: Optional[str] = None):
    """Fetch recent privacy-safe audit log events."""
    if not pipeline.audit_logger:
        return {"events": []}
    events = pipeline.audit_logger.get_events(limit=limit, category=category)
    return {"events": events}


@app.get("/audit/stats", tags=["Audit"])
async def get_audit_stats():
    """Fetch KPI statistics for the security dashboard."""
    if not pipeline.audit_logger:
        return {}
    return pipeline.audit_logger.get_stats()


# ── File Leak Detection & RAG Ingestion Endpoints ────────────────────────────

@app.post("/ingest", response_model=IngestResponse, tags=["File Leak Detection"])
async def ingest_document(req: IngestRequest):
    """
    Ingest a document into RAG knowledge base after deep security inspection:
    magic byte sniffing, limits enforcement, sandbox parsing, leak detection,
    and 64-bit SimHash DLP fingerprint registration.
    """
    if not pipeline.rag_engine:
        raise HTTPException(status_code=500, detail="RAG engine not initialized")

    try:
        raw_bytes = base64.b64decode(req.content_base64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {e}")

    result = pipeline.rag_engine.ingest_file(
        filename=req.filename,
        file_bytes=raw_bytes,
        user_id=req.user_id or "admin",
        role=req.role or "admin",
        title=req.title,
        dept=req.dept or "general",
        tags=req.tags
    )
    return IngestResponse(**result)


@app.post("/ingest/upload", response_model=IngestResponse, tags=["File Leak Detection"])
async def ingest_document_upload(
    file: UploadFile = File(...),
    title: Optional[str] = Form(None),
    dept: Optional[str] = Form("general"),
    user_id: Optional[str] = Form("admin"),
    role: Optional[str] = Form("admin"),
):
    """Multipart document upload for RAG indexing with leak detection."""
    if not pipeline.rag_engine:
        raise HTTPException(status_code=500, detail="RAG engine not initialized")

    raw_bytes = await file.read()
    result = pipeline.rag_engine.ingest_file(
        filename=file.filename or "uploaded_file",
        file_bytes=raw_bytes,
        user_id=user_id or "admin",
        role=role or "admin",
        title=title or file.filename,
        dept=dept or "general"
    )
    return IngestResponse(**result)


@app.post("/chat/upload", response_model=ChatResponse, tags=["Gateway"])
async def chat_with_files(
    message: str = Form(...),
    user_id: str = Form("anonymous"),
    role: str = Form("intern"),
    session_id: Optional[str] = Form(None),
    files: List[UploadFile] = File(default_factory=list),
):
    """
    Chat endpoint supporting multipart file attachments (images, PDFs, DOCX, etc.).
    Extracts, inspects, and masks/redacts file contents before LLM forwarding.
    """
    attachments = []
    for f in files:
        if f.filename:
            content = await f.read()
            if content:
                b64_content = base64.b64encode(content).decode("ascii")
                attachments.append(FileAttachment(
                    filename=f.filename,
                    content_base64=b64_content,
                    mime_type=f.content_type
                ))

    req = ChatRequest(
        user_id=user_id,
        role=role,
        message=message,
        session_id=session_id,
        attachments=attachments if attachments else None
    )
    return pipeline.process(req)


@app.get("/files/dlp/fingerprints", tags=["File Leak Detection"])
async def get_dlp_fingerprints():
    """Retrieve all registered 64-bit SimHash DLP fingerprints and registry stats."""
    from gateway.files.dlp import get_dlp_registry
    reg = get_dlp_registry()
    return {
        "count": len(reg.fingerprints),
        "fingerprints": reg.fingerprints
    }


@app.post("/files/dlp/register", tags=["File Leak Detection"])
async def register_dlp_fingerprint(
    doc_id: str = Form(...),
    title: str = Form(...),
    text: str = Form(...),
    tags: Optional[str] = Form("")
):
    """Register a custom sensitive/restricted text document into the DLP registry."""
    from gateway.files.dlp import get_dlp_registry, simhash_to_hex
    reg = get_dlp_registry()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    simhash_val = reg.register_document(doc_id=doc_id, title=title, text=text, tags=tag_list)
    return {
        "status": "registered",
        "doc_id": doc_id,
        "title": title,
        "simhash": simhash_to_hex(simhash_val)
    }


@app.get("/files/stats", tags=["File Leak Detection"])
async def get_file_leak_stats():
    """Aggregated inspection metrics for attached files and documents."""
    if not pipeline.audit_logger:
        return {"total_files_scanned": 0, "file_findings": []}
    
    events = pipeline.audit_logger.get_events(limit=500)
    file_categories = [
        "aadhaar_card_image", "pan_card_image", "payment_card_image",
        "passport_image", "terminal_screenshot_image", "macro_embedded_executable",
        "bulk_personal_data_leak", "dlp_restricted_document_match",
        "steganography_appended_payload", "archive_security_violation",
        "extension_spoofing_mismatch", "executable_binary_embedded",
        "file_size_exceeded", "page_budget_exceeded"
    ]
    file_events = [e for e in events if e.get("category") in file_categories]
    return {
        "total_file_security_events": len(file_events),
        "events": file_events[:50]
    }

