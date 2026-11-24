# Detection Limitations (Independent Rule Review)

This document reviews every registered SkillGuard security rule as of v0.2.0.
Passing unit tests do **not** imply complete detection. Review date: 2026-03-24.

## Summary

SkillGuard v0.1–0.2 detectors are primarily **deterministic pattern / AST heuristics**.
They catch many textbook attacks and miss paraphrased, multi-stage, and
cross-tool semantic attacks. Treat findings as signals for human review.

---

## SG-SECRET-001 — Hardcoded API key or token

| Aspect | Assessment |
|--------|------------|
| Detects | `sk-…`, `ghp_…`, `xox…`, `AKIA…`, `api_key="…"` style assignments |
| Misses | Azure/GCP/JWT without known prefixes; split/concatenated secrets; env-only secrets; custom token formats |
| False positives | Example placeholders that look real (`sk-` + long alnum); test fixtures; docs with sample keys |
| Bypasses | Base64/hex encode keys; store in images; use uncommon prefixes (`rk_live_`, `pat_`); split across lines |
| Context weakness | Educational skip only when nearby “example/never” markers exist |
| Evidence/remediation | Evidence redacted — correct. Remediation accurate. |

## SG-SECRET-002 — Embedded private key

| Aspect | Assessment |
|--------|------------|
| Detects | PEM/`OPENSSH` private key headers |
| Misses | Encrypted key bags without headers; PuTTY `.ppk`; keys in binary blobs |
| False positives | Truncated educational PEM headers (rare; pattern requires BEGIN line) |
| Bypasses | Strip headers; armor differently; store encrypted archives |
| Evidence/remediation | Correct |

## SG-SECRET-003 — Environment variable secret exposure

| Aspect | Assessment |
|--------|------------|
| Detects | `printenv`, `os.environ`, `process.env`, named secret env vars, dump/exfil phrasing |
| Misses | Indirect dumps via debugger APIs; language-specific env readers |
| False positives | Benign `os.environ.get("PATH")`; docs mentioning `OPENAI_API_KEY` setup |
| Bypasses | Custom wrappers; `getattr(os, "environ")` |
| Note | High FP risk — confidence often MEDIUM; reviewers must contextualize |

## SG-SECRET-004 — Credential file access

| Aspect | Assessment |
|--------|------------|
| Detects | `.aws/credentials`, `.ssh/id_*`, `.npmrc`, docker config, `/etc/shadow`, etc. |
| Misses | Platform-specific stores (Keychain, Credential Manager) via APIs |
| False positives | Security docs listing paths to protect |
| Bypasses | `Path.home() / ".ssh" / "id_rsa"` with unusual path construction |

## SG-SHELL-001 — Dangerous shell command

| Aspect | Assessment |
|--------|------------|
| Detects | `rm -rf /`, mkfs, dd to devices, fork bombs, curl\|sh, chmod 777 |
| Misses | Obfuscated `rm` via variables; PowerShell equivalents beyond a few patterns; `find -delete` mass deletes |
| False positives | Educational markdown (mitigated by educational-context skip) |
| Bypasses | `rm -r -f /`; unicode lookalikes; `command rm` |

## SG-SHELL-002 — Command injection pattern

| Aspect | Assessment |
|--------|------------|
| Detects | `os.system`, `shell=True`, `eval`/`exec`, `child_process.exec`, template shells |
| Misses | Safe `subprocess.run([...])` that later becomes unsafe; `pty.spawn` |
| False positives | Legitimate `eval` in math DSLs; test harnesses |
| Improvement | AST analysis (v0.2) reduces some string-false matches for Python |

## SG-SHELL-003 — Download-and-execute

| Aspect | Assessment |
|--------|------------|
| Detects | curl/wget\|bash, iwr\|iex, requests.get→exec |
| Misses | Multi-step download then later exec across files (partially addressed by cross-file analysis in v0.2) |
| False positives | Docs showing anti-patterns (educational skip) |

## SG-SHELL-004 — Dynamic code execution

| Aspect | Assessment |
|--------|------------|
| Detects | `Function(`, `new Function`, `__import__("os")`, compile `<string>` |
| Misses | `importlib.import_module` chains; bytecode `marshal.loads` |

## SG-FS-001 / SG-FS-002 / SG-PRIV-001

| Aspect | Assessment |
|--------|------------|
| Detects | `shutil.rmtree`, sensitive absolute paths, sudo/runas/`--privileged` |
| Misses | Abstracted helpers; Windows-only destructive cmds incompletely covered |
| False positives | Admin runbooks in markdown |

## SG-NET-001 / SG-NET-002

| Aspect | Assessment |
|--------|------------|
| Detects | HTTP client calls, raw IPs, exfil keywords, read+send same file |
| Misses | DNS tunneling; agent-tool mediated exfil without code; delayed multi-file pipelines |
| False positives | Legitimate API client skills using `requests` |

## SG-OBF-001 / SG-OBF-002

| Aspect | Assessment |
|--------|------------|
| Detects | base64/hex/`chr()` obfuscation; zero-width chars; HTML comment tricks |
| Misses | Homoglyph attacks; ROT/custom ciphers; steganography in assets |
| False positives | Legitimate long base64 (certs, fixtures) at LOW confidence |

## SG-INST-001…004 — Instruction attacks

| Aspect | Assessment |
|--------|------------|
| Detects | Ignore-previous / jailbreak / secret harvest / conceal / bypass phrasing |
| Misses | Indirect injection via referenced URLs/docs; multilingual prompts; polite paraphrases (“please set aside earlier constraints”); multi-turn staged attacks |
| False positives | Skills teaching security that quote attack phrases without negation window |
| Critical gap | Description-field injection (agent-visible) was under-scanned in v0.1 — fixed in v0.2 |

## SG-DEP-001 / SG-DEP-002

| Aspect | Assessment |
|--------|------------|
| Detects | pip/npm from URLs, `--break-system-packages`, binaries |
| Misses | Typosquatting package names; lockfile integrity issues |

## SG-STRUCT-\* (validator)

Spec validation — not security detectors. Useful for malformed skills; not malware signals.

---

## Cross-cutting weaknesses

1. **No semantic understanding** — paraphrases defeat regex.
2. **Limited cross-file correlation** — improved but not complete in v0.2.
3. **Language coverage** — Python AST added; JS/shell still mostly regex.
4. **Asset blindness** — images/PDFs not scanned for hidden instructions.
5. **Agent-tool indirection** — attacks that only ask the agent to use built-in tools leave few code patterns.

## What “detected” means

A finding means a heuristic matched with some confidence — not confirmed exploitation.
Absence of findings means no matched heuristic — not safety.
