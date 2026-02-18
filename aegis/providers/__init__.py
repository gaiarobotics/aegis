"""AEGIS provider wrappers for LLM client interception."""

from aegis.providers.anthropic import AnthropicWrapper, detect_anthropic
from aegis.providers.base import BaseWrapper, WrappedClient
from aegis.providers.generic import GenericWrapper, detect_generic
from aegis.providers.openai import OpenAIWrapper, detect_openai

__all__ = [
    "AnthropicWrapper",
    "BaseWrapper",
    "GenericWrapper",
    "OpenAIWrapper",
    "WrappedClient",
    "detect_anthropic",
    "detect_generic",
    "detect_openai",
]
