"""
Vercel serverless entry point.

Model artifacts live in api/models/ (included via vercel.json includeFiles).
They load once per warm container. The top-level `app` name is required by
Vercel's Python runtime entrypoint detection.
"""
import os
import sys

# make /var/task importable (detector.py, app.py live at the bundle root)
TASK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TASK_ROOT)

from app import app  # noqa: E402,F401  (ASGI app expected by Vercel)

application = app  # noqa: F811  (alias for WSGI-style detection)
handler = app
