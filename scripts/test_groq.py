import os
import requests
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("GROQ_API_KEY")

print("Key loaded:", key[:10] + "..." if key else "NONE FOUND")

response = requests.post(
    "https://api.groq.com/openai/v1/chat/completions",
    headers={"Authorization": f"Bearer {key}"},
    json={
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "user", "content": "Say hello in one sentence."}]
    }
)

print("Status code:", response.status_code)
print("Full response:", response.text)
