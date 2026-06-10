"""List Sonnet/Haiku/Opus exact IDs available on OpenRouter under the current key."""
import json
import os
import urllib.request

token = open("/workspace/.openrouter_token").read().strip()
req = urllib.request.Request(
    "https://openrouter.ai/api/v1/models",
    headers={"Authorization": f"Bearer {token}"},
)
data = json.loads(urllib.request.urlopen(req).read())

prefixes = ("anthropic/claude-sonnet-", "anthropic/claude-haiku-",
            "anthropic/claude-opus-", "anthropic/claude-fable-")
for m in data.get("data", []):
    mid = m.get("id", "")
    if mid.startswith(prefixes):
        pricing = m.get("pricing", {})
        pin = pricing.get("prompt", "?")
        pout = pricing.get("completion", "?")
        print(f"  {mid:50s} in={pin} out={pout}")
