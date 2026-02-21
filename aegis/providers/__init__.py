"""AEGIS provider wrappers for LLM client interception."""

from aegis.providers.anthropic import AnthropicWrapper, detect_anthropic
from aegis.providers.base import BaseWrapper, WrappedClient
from aegis.providers.generic import GenericWrapper, detect_generic
from aegis.providers.ollama import OllamaWrapper, detect_ollama
from aegis.providers.openai import OpenAIWrapper, detect_openai
from aegis.providers.vllm import VLLMWrapper, detect_vllm

__all__ = [
    "AnthropicWrapper",
    "BaseWrapper",
    "GenericWrapper",
    "OllamaWrapper",
    "OpenAIWrapper",
    "VLLMWrapper",
    "WrappedClient",
    "detect_anthropic",
    "detect_generic",
    "detect_ollama",
    "detect_openai",
    "detect_vllm",
]
