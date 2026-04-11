"""Mock OpenAI-compatible LLM server for e2e testing.

Returns deterministic, realistic responses that pass AEGIS output
sanitization without triggering false positives. The content reads
like a real business analysis — no authority markers, no gibberish.
"""

import time
import hashlib

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Mock LLM")

ANALYSIS_RESPONSE = (
    "Based on the provided quarterly report, here is a summary of key findings.\n\n"
    "Revenue grew by 12% compared to the previous quarter, driven primarily by "
    "expansion in the enterprise segment. The North American market contributed 62% "
    "of total revenue, while EMEA showed the strongest relative growth at 18% "
    "quarter-over-quarter.\n\n"
    "Operating expenses increased by 8%, which is below the revenue growth rate, "
    "indicating improving operational efficiency. The engineering department "
    "headcount grew by 15 positions, concentrated in the platform infrastructure "
    "team.\n\n"
    "Customer retention remained strong at 94%, though new customer acquisition "
    "costs increased by 6%. The sales pipeline shows healthy momentum with a "
    "weighted pipeline value 22% above the same period last year.\n\n"
    "Key risks include supply chain dependencies in the hardware division and "
    "pending regulatory changes in the EU market. The report recommends "
    "accelerating the diversification strategy outlined in the previous quarter."
)


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "mock-analyst"
    messages: list[ChatMessage]
    temperature: float = 1.0
    max_tokens: int | None = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/chat/completions")
def chat_completions(request: ChatRequest):
    # Deterministic ID from input for reproducibility
    input_hash = hashlib.md5(
        request.messages[-1].content.encode() if request.messages else b""
    ).hexdigest()[:8]

    return {
        "id": f"chatcmpl-mock-{input_hash}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": ANALYSIS_RESPONSE,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": sum(len(m.content.split()) for m in request.messages),
            "completion_tokens": len(ANALYSIS_RESPONSE.split()),
            "total_tokens": (
                sum(len(m.content.split()) for m in request.messages)
                + len(ANALYSIS_RESPONSE.split())
            ),
        },
    }
