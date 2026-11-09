"""
Core security pipeline orchestrating normalization, detection, policy enforcement,
access-controlled RAG, LLM generation, output guarding, and privacy-safe audit logging.
"""

import time
import logging
import uuid
from typing import Dict, Any, List, Optional, Tuple

from gateway.models import ChatRequest, ChatResponse, Finding, FindingSummary
from gateway.llm import LLMAdapter

logger = logging.getLogger("gateway.pipeline")


class SecurityPipeline:
    """Security gateway pipeline implementing multi-layer defense in depth."""

    def __init__(self):
        self.llm = LLMAdapter()
        # Sub-modules will be initialized in their respective phases
        self.policy_engine = None
        self.audit_logger = None
        self.rag_engine = None
        self.output_guard = None
        self.file_inspector = None
        self.approval_queue: Dict[str, Dict[str, Any]] = {}

    def set_file_inspector(self, inspector):
        self.file_inspector = inspector

    def get_file_inspector(self):
        if self.file_inspector is None:
            from gateway.files.inspector import MasterFileInspector
            self.file_inspector = MasterFileInspector(
                policy_engine=self.policy_engine,
                audit_logger=self.audit_logger
            )
        return self.file_inspector

    def set_policy_engine(self, engine):
        self.policy_engine = engine
        if self.file_inspector:
            self.file_inspector.policy_engine = engine

    def set_audit_logger(self, logger_instance):
        self.audit_logger = logger_instance
        if self.file_inspector:
            self.file_inspector.audit_logger = logger_instance

    def set_rag_engine(self, rag):
        self.rag_engine = rag

    def set_output_guard(self, guard):
        self.output_guard = guard

    def process(self, request: ChatRequest) -> ChatResponse:
        """Run the full security pipeline on a chat request."""
        start_time = time.perf_counter()
        request_id = str(uuid.uuid4())
        stage_latencies: Dict[str, float] = {}

        # 1. Normalization Stage
        t0 = time.perf_counter()
        normalized_text = request.message
        decoded_payloads: List[str] = []
        try:
            from gateway.normalize import normalize_input
            normalized_text, decoded_payloads = normalize_input(request.message)
        except ImportError:
            pass
        except Exception as e:
            logger.error(f"Normalization failed: {e}")
        stage_latencies["normalization"] = round((time.perf_counter() - t0) * 1000, 2)

        # 2. Input Detection Stage (PII, Secrets, Confidentiality, Injection, Robust Identifiers)
        t0 = time.perf_counter()
        findings: List[Finding] = []
        detector_failed = False
        try:
            findings = self._run_input_detectors(
                request.message,
                normalized_text,
                decoded_payloads,
                request.role,
                session_id=request.session_id,
            )
        except Exception as e:
            logger.error(f"Detector crashed (failing closed): {e}")
            detector_failed = True

        stage_latencies["detection"] = round((time.perf_counter() - t0) * 1000, 2)

        # 2.5 File Attachment Inspection Stage
        file_results: List[Dict[str, Any]] = []
        extracted_docs_context: List[str] = []
        file_blocked = False
        if request.attachments:
            t_files = time.perf_counter()
            import base64
            from gateway.detectors.injection import wrap_untrusted_document
            inspector = self.get_file_inspector()
            for att in request.attachments:
                try:
                    raw_bytes = base64.b64decode(att.content_base64)
                    f_res = inspector.inspect_file(
                        file_bytes=raw_bytes,
                        filename=att.filename,
                        user_id=request.user_id,
                        role=request.role,
                        request_id=request_id
                    )
                    file_results.append(f_res.to_dict())

                    # Forward file findings into unified pipeline findings list
                    for ff in f_res.findings:
                        findings.append(Finding(
                            category=ff.category,
                            start=0,
                            end=0,
                            score=ff.score,
                            detector=ff.detector,
                            matched_text=ff.matched_text
                        ))

                    if f_res.is_blocked:
                        file_blocked = True
                    else:
                        text_to_use = f_res.redacted_text if f_res.redacted_text is not None else f_res.extracted_text
                        if text_to_use and text_to_use.strip():
                            wrapped = wrap_untrusted_document(text_to_use.strip(), filename=att.filename)
                            extracted_docs_context.append(wrapped)
                except Exception as e:
                    logger.error(f"Error inspecting attachment {att.filename}: {e}")
                    findings.append(Finding(
                        category="archive_security_violation",
                        start=0,
                        end=0,
                        score=1.0,
                        detector="file_inspector",
                        matched_text=f"crash_{att.filename}"
                    ))
                    file_blocked = True

            stage_latencies["file_inspection"] = round((time.perf_counter() - t_files) * 1000, 2)

        # Fail closed check
        if detector_failed:
            total_latency = round((time.perf_counter() - start_time) * 1000, 2)
            if self.audit_logger:
                self.audit_logger.log_event(
                    request_id=request_id,
                    user_id=request.user_id,
                    role=request.role,
                    direction="input",
                    category="system_error",
                    policy_id="fail_closed",
                    action="block",
                    score=1.0,
                    matched_value="detector_crash",
                    latency_ms=total_latency,
                    stage_latencies=stage_latencies
                )
            return ChatResponse(
                request_id=request_id,
                answer="Request blocked: Gateway security inspection failed safely (fail-closed policy).",
                blocked=True,
                actions=["block"],
                findings_summary=[FindingSummary(category="system_error", detector="gateway", score=1.0, action="block")],
                latency_ms=total_latency,
                stage_latencies=stage_latencies,
                file_results=file_results
            )

        # 3. Policy Engine Evaluation
        t0 = time.perf_counter()
        overall_action = "allow"
        evaluated_findings: List[Tuple[Finding, str, str]] = []  # (finding, action, policy_id)
        if self.policy_engine:
            overall_action, evaluated_findings = self.policy_engine.evaluate(findings, role=request.role)
        else:
            evaluated_findings = [(f, "allow", "default_allow") for f in findings]

        if file_blocked:
            overall_action = "block"
        stage_latencies["policy"] = round((time.perf_counter() - t0) * 1000, 2)

        # Build privacy-safe finding summaries
        finding_summaries = []
        for f, act, _pol in evaluated_findings:
            preview = None
            if f.matched_text:
                preview = f.matched_text[-4:] if len(f.matched_text) >= 4 else f.matched_text
            finding_summaries.append(FindingSummary(
                category=f.category,
                detector=f.detector,
                score=round(f.score, 3),
                action=act,
                preview=preview
            ))

        # Log findings to audit logger
        if self.audit_logger:
            for f, act, pol_id in evaluated_findings:
                self.audit_logger.log_event(
                    request_id=request_id,
                    user_id=request.user_id,
                    role=request.role,
                    direction="input",
                    category=f.category,
                    policy_id=pol_id,
                    action=act,
                    score=f.score,
                    matched_value=f.matched_text or "",
                    latency_ms=stage_latencies["detection"],
                    stage_latencies=stage_latencies
                )

        # 4. Handle BLOCK Action
        if overall_action == "block":
            total_latency = round((time.perf_counter() - start_time) * 1000, 2)
            block_reasons = [f.category for f, act, _ in evaluated_findings if act == "block"]
            reason_str = ", ".join(set(block_reasons)) if block_reasons else "security policy violation"
            return ChatResponse(
                request_id=request_id,
                answer=f"Request blocked by security policy: {reason_str}.",
                blocked=True,
                actions=["block"],
                findings_summary=finding_summaries,
                latency_ms=total_latency,
                stage_latencies=stage_latencies,
                file_results=file_results
            )

        # 5. Handle REQUIRE_APPROVAL Action
        if overall_action == "require_approval":
            total_latency = round((time.perf_counter() - start_time) * 1000, 2)
            approval_id = str(uuid.uuid4())
            self.approval_queue[approval_id] = {
                "id": approval_id,
                "request_id": request_id,
                "user_id": request.user_id,
                "role": request.role,
                "message": request.message,
                "findings": finding_summaries,
                "status": "pending",
                "timestamp": time.time(),
                "file_results": file_results
            }
            return ChatResponse(
                request_id=request_id,
                answer="Your request has been held for administrative security approval.",
                blocked=False,
                actions=["require_approval"],
                findings_summary=finding_summaries,
                latency_ms=total_latency,
                stage_latencies=stage_latencies,
                approval_id=approval_id,
                file_results=file_results
            )

        # 6. Masking & Redaction (prefer MASK over BLOCK)
        sanitized_message = request.message
        if self.policy_engine and any(act in ("mask", "redact") for _, act, _ in evaluated_findings):
            sanitized_message = self.policy_engine.mask_spans(request.message, evaluated_findings)

        if extracted_docs_context:
            sanitized_message = sanitized_message + "\n\n" + "\n\n".join(extracted_docs_context)

        # 7. Access-Controlled RAG Retrieval
        t0 = time.perf_counter()
        rag_context = ""
        if self.rag_engine:
            rag_context = self.rag_engine.retrieve(
                query=sanitized_message,
                user_id=request.user_id,
                role=request.role,
                request_id=request_id
            )
        stage_latencies["rag"] = round((time.perf_counter() - t0) * 1000, 2)

        # 8. LLM Invocation with Canary Token
        t0 = time.perf_counter()
        system_prompt = "You are a secure, helpful corporate assistant."
        canary_token = None
        if self.output_guard:
            system_prompt, canary_token = self.output_guard.inject_canary(system_prompt)

        raw_llm_response = self.llm.generate(
            prompt=sanitized_message,
            system_prompt=system_prompt,
            context=rag_context
        )
        stage_latencies["llm"] = round((time.perf_counter() - t0) * 1000, 2)

        # 9. Output Guard
        t0 = time.perf_counter()
        guarded_response = raw_llm_response
        combined_actions = [overall_action]
        if self.output_guard:
            guarded_response, out_actions, out_findings = self.output_guard.inspect_output(
                output_text=raw_llm_response,
                canary_token=canary_token,
                role=request.role,
                user_id=request.user_id,
                request_id=request_id,
                stage_latencies=stage_latencies
            )
            combined_actions.extend(out_actions)
            # Add output findings to summaries
            for of in out_findings:
                finding_summaries.append(FindingSummary(
                    category=of.category,
                    detector=of.detector,
                    score=round(of.score, 3),
                    action="output_guard",
                    preview=of.matched_text[-4:] if of.matched_text and len(of.matched_text) >= 4 else None
                ))
        stage_latencies["output_guard"] = round((time.perf_counter() - t0) * 1000, 2)

        total_latency = round((time.perf_counter() - start_time) * 1000, 2)
        unique_actions = list(dict.fromkeys(combined_actions))

        return ChatResponse(
            request_id=request_id,
            answer=guarded_response,
            blocked=any("block" in a for a in unique_actions),
            actions=unique_actions,
            findings_summary=finding_summaries,
            latency_ms=total_latency,
            stage_latencies=stage_latencies,
            masked_message=sanitized_message if sanitized_message != request.message else None,
            file_results=file_results
        )

    def _run_input_detectors(
        self,
        raw_text: str,
        normalized_text: str,
        decoded_payloads: List[str],
        role: str,
        session_id: Optional[str] = None,
    ) -> List[Finding]:
        """Run all input detectors across raw and normalized representations."""
        findings: List[Finding] = []

        # Robust Identifier Detector (Aadhaar & PAN under heavy obfuscation & multi-turn split)
        try:
            from gateway.detectors.robust_ids import detect as detect_robust_ids
            findings.extend(detect_robust_ids(raw_text, session_id=session_id))
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Robust identifier detector error: {e}")

        # PII Detector (second opinion)
        try:
            from gateway.detectors.pii import scan_pii
            findings.extend(scan_pii(raw_text))
        except ImportError:
            pass

        # Secrets Detector
        try:
            from gateway.detectors.secrets import scan_secrets
            findings.extend(scan_secrets(raw_text))
            # Also scan decoded payloads if any
            for payload in decoded_payloads:
                findings.extend(scan_secrets(payload))
        except ImportError:
            pass

        # Confidentiality & Source Code Detector
        try:
            from gateway.detectors.confidential import scan_confidential
            findings.extend(scan_confidential(raw_text))
        except ImportError:
            pass

        # Injection Shield
        try:
            from gateway.detectors.injection import scan_injection
            findings.extend(scan_injection(raw_text, normalized_text, decoded_payloads))
        except ImportError:
            pass

        return findings
