"""AEGIS: Agent Epidemiological Guardian & Immune System."""

from aegis.core import killswitch
from aegis.shield import Shield, ThreatBlockedError

__version__ = "0.1.0"


def wrap(client, **kwargs):
    """Wrap an LLM client with default AEGIS protection.

    Creates a Shield with default config and wraps the client.

    Args:
        client: The LLM client to wrap (Anthropic, OpenAI, or generic).
        **kwargs: Additional arguments passed to Shield constructor
                  (policy, modules, mode).

    Returns:
        A wrapped client with AEGIS protection.

    Example::

        import aegis
        import anthropic

        client = aegis.wrap(anthropic.Anthropic())
    """
    shield = Shield(**kwargs)
    return shield.wrap(client)


__all__ = [
    "Shield",
    "ThreatBlockedError",
    "killswitch",
    "wrap",
    "__version__",
]
