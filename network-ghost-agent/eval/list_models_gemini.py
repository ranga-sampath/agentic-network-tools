#!/usr/bin/env python3
"""List Gemini models available to the configured API key.

Usage:
    python eval/list_models_gemini.py
"""
import os
import re
import sys
from pathlib import Path

# Load GEMINI_API_KEY from demo/config.env if not already in environment
api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    config = Path(__file__).parent.parent / "demo" / "config.env"
    for line in config.read_text().splitlines():
        m = re.match(r'GEMINI_API_KEY=["\']?(.*?)["\']?\s*$', line.strip())
        if m:
            api_key = m.group(1)
            break

if not api_key:
    sys.exit("[ERROR] GEMINI_API_KEY not found in environment or demo/config.env")

from google import genai  # noqa: E402

client = genai.Client(api_key=api_key)
print("Models available on this account (generateContent capable):")
for model in client.models.list():
    if "generateContent" in (model.supported_actions or []):
        print(f"  {model.name}")
