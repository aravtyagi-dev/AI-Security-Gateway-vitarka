"""
Data models and shared contracts for AI Security Gateway.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid
import time


class Finding(BaseModel):
    """Represents a security finding from any detector."""
    category: str
    start: int
    end: int
    score: float = Field(ge=0.0, le=1.0)
    detector: str
    matched_text: Optional[str] = None  # Ephemeral: kept in-memory for masking/hashing only


class FileAttachment(BaseModel):
    """File attachment encoded in Base64 for chat prompt processing."""
    filename: str
    content_base64: str
    mime_type: Optional[str] = None


class ChatRequest(BaseModel):
    """Standard chat request payload."""
    user_id: str = "anonymous"
    role: str = "intern"
    message: str
    session_id: Optional[str] = None
    attachments: Optional[List[FileAttachment]] = None


class FindingSummary(BaseModel):
    """Privacy-safe summary of a finding without sensitive values."""
    category: str
    detector: str
    score: float
    action: str
    preview: Optional[str] = None  # Last 4 chars only (masked)


class ChatResponse(BaseModel):
    """Standard chat response payload."""
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    answer: str
    blocked: bool = False
    actions: List[str] = Field(default_factory=list)
    findings_summary: List[FindingSummary] = Field(default_factory=list)
    latency_ms: float = 0.0
    stage_latencies: Dict[str, float] = Field(default_factory=dict)
    approval_id: Optional[str] = None
    masked_message: Optional[str] = None  # The sanitized version sent to the LLM (for UI inspection)
    file_results: List[Dict[str, Any]] = Field(default_factory=list)


class IngestRequest(BaseModel):
    """Document upload payload for RAG knowledge base ingestion."""
    filename: str
    content_base64: str
    title: Optional[str] = None
    dept: Optional[str] = "general"
    user_id: Optional[str] = "admin"
    role: Optional[str] = "admin"
    tags: Optional[List[str]] = Field(default_factory=list)


class IngestResponse(BaseModel):
    """Result of RAG document ingestion."""
    success: bool
    doc_id: Optional[str] = None
    filename: str
    status: str  # "indexed", "blocked", "quarantined"
    message: str
    findings_summary: List[FindingSummary] = Field(default_factory=list)
    simhash: Optional[str] = None
    file_inspection: Optional[Dict[str, Any]] = None


# OpenAI-compatible API models
class OpenAIChatMessage(BaseModel):
    role: str
    content: str


class OpenAIChatCompletionRequest(BaseModel):
    model: Optional[str] = "ai-gateway"
    messages: List[OpenAIChatMessage]
    user: Optional[str] = None
    temperature: Optional[float] = 0.7
    stream: Optional[bool] = False


class OpenAIChoiceMessage(BaseModel):
    role: str = "assistant"
    content: str


class OpenAIChoice(BaseModel):
    index: int = 0
    message: OpenAIChoiceMessage
    finish_reason: str = "stop"


class OpenAIUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class OpenAIChatCompletionResponse(BaseModel):
    id: str = Field(default_factory=lambda: f"chatcmpl-{uuid.uuid4().hex[:12]}")
    object: str = "chat.completion"
    created: int = Field(default_factory=lambda: int(time.time()))
    model: str = "ai-gateway"
    choices: List[OpenAIChoice]
    usage: OpenAIUsage = Field(default_factory=OpenAIUsage)
