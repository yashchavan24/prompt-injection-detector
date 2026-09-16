"""
Legacy entry point kept for backwards compatibility.

Since v3, the production model is lightweight (~4 MB, no torch / no
sentence-transformers), so there is no longer a need for a separate "lite"
app -- everything runs from app.py. `uvicorn app_deploy:app` still works.
"""
from app import (  # noqa: F401
    app,
    check_prompt,
    protected_chat,
    score_text,
)
