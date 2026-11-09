"""
LLM Adapter supporting Gemini, OpenAI-compatible, Ollama, and Mock providers.
Defaults to 'mock' when no external API key is configured.
"""

import os
from typing import Optional, List, Dict, Any
import httpx
import logging

logger = logging.getLogger("gateway.llm")


class LLMAdapter:
    """Multi-provider LLM interface with fallback to mock."""

    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "").lower()
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.openai_base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model_name = os.getenv("LLM_MODEL", "default")

        # Determine effective provider
        if not self.provider:
            if self.gemini_api_key:
                self.provider = "gemini"
            elif self.openai_api_key:
                self.provider = "openai_compatible"
            else:
                self.provider = "mock"

        if self.provider not in ("gemini", "openai_compatible", "ollama", "mock"):
            logger.warning(f"Unknown LLM_PROVIDER '{self.provider}', falling back to 'mock'")
            self.provider = "mock"

        logger.info(f"Initialized LLM Adapter with provider: {self.provider}")

    def generate(self, prompt: str, system_prompt: Optional[str] = None, context: Optional[str] = None) -> str:
        """Generate a response using the configured provider."""
        full_system = system_prompt or "You are a secure, helpful corporate AI assistant."
        
        if self.provider == "gemini":
            return self._call_gemini(prompt, full_system, context)
        elif self.provider == "openai_compatible":
            return self._call_openai(prompt, full_system, context)
        elif self.provider == "ollama":
            return self._call_ollama(prompt, full_system, context)
        else:
            return self._call_mock(prompt, full_system, context)

    def _call_mock(self, prompt: str, system_prompt: str, context: Optional[str] = None) -> str:
        """Deterministic canned answer for offline/mock mode."""
        prompt_lower = prompt.lower()
        
        # Check context first for RAG responses
        if context:
            ctx_lower = context.lower()
            if "salary" in prompt_lower or "salary" in ctx_lower:
                return (
                    "Based on the authorized HR compensation policy in context: "
                    "Level 1: $50,000, Level 2: $75,000, Level 3: $100,000, Level 4 (Exec/Mgr): $140,000+. "
                    f"Retrieved context verified."
                )
            if "q3 forecast" in prompt_lower or "revenue" in prompt_lower or "q3 forecast" in ctx_lower:
                return "According to the Finance Q3 forecast document: Projected revenue is $12.4M with 18% EBITDA margin."
            if "handbook" in prompt_lower or "leave" in prompt_lower or "handbook" in ctx_lower:
                return "Per the Employee Handbook: Standard annual paid leave is 20 days with 10 days sick leave."
            return f"Mock Assistant: Processed query using context. Context length: {len(context)} chars."

        # Canned responses for direct prompts
        if "hello" in prompt_lower or "hi" in prompt_lower:
            return "Hello! I am your AI assistant. How can I assist you with your tasks today?"
        if "reset my password" in prompt_lower or "password reset" in prompt_lower:
            return "To reset your corporate password, please visit https://identity.internal/self-service or contact IT helpdesk at ext. 4357."
        if "aadhaar checksum" in prompt_lower or "verhoeff" in prompt_lower:
            return "The Aadhaar number uses the Verhoeff algorithm (base-10 check digit) based on the dihedral group D5 to detect all single-digit transcription errors."
        if "salary" in prompt_lower:
            return "I do not have access to salary information in this session. Please check with HR or authorized portals."
            
        return f"Mock Assistant Response: Processed request successfully for '{prompt[:40]}...'."

    def _call_gemini(self, prompt: str, system_prompt: str, context: Optional[str] = None) -> str:
        """Call Google Gemini API."""
        if not self.gemini_api_key:
            return self._call_mock(prompt, system_prompt, context)
        try:
            from google import genai
            client = genai.Client(api_key=self.gemini_api_key)
            combined_prompt = ""
            if system_prompt:
                combined_prompt += f"System Instruction: {system_prompt}\n\n"
            if context:
                combined_prompt += f"Context Documents:\n{context}\n\n"
            combined_prompt += f"User Request: {prompt}"
            
            model = self.model_name if self.model_name != "default" else "gemini-2.5-flash"
            response = client.models.generate_content(
                model=model,
                contents=combined_prompt,
            )
            return response.text or ""
        except Exception as e:
            logger.error(f"Gemini generation error: {e}")
            return f"Error communicating with Gemini provider: {str(e)}"

    def _call_openai(self, prompt: str, system_prompt: str, context: Optional[str] = None) -> str:
        """Call OpenAI-compatible endpoint."""
        messages = [{"role": "system", "content": system_prompt}]
        user_content = f"Context:\n{context}\n\nQuestion: {prompt}" if context else prompt
        messages.append({"role": "user", "content": user_content})

        try:
            model = self.model_name if self.model_name != "default" else "gpt-4o-mini"
            resp = httpx.post(
                f"{self.openai_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {self.openai_api_key}"},
                json={"model": model, "messages": messages, "temperature": 0.2},
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"OpenAI compatible error: {e}")
            return f"Error communicating with OpenAI provider: {str(e)}"

    def _call_ollama(self, prompt: str, system_prompt: str, context: Optional[str] = None) -> str:
        """Call local Ollama server."""
        full_prompt = f"{system_prompt}\n\nContext:\n{context}\n\nPrompt:\n{prompt}" if context else f"{system_prompt}\n\n{prompt}"
        try:
            model = self.model_name if self.model_name != "default" else "llama3"
            resp = httpx.post(
                f"{self.ollama_base_url.rstrip('/')}/api/generate",
                json={"model": model, "prompt": full_prompt, "stream": False},
                timeout=45.0,
            )
            resp.raise_for_status()
            return resp.json().get("response", "")
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return f"Error communicating with Ollama provider: {str(e)}"
