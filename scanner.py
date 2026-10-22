"""vibescan: static checks for common security mistakes in AI-written repos. Stdlib only."""
import io, json, re, urllib.request, zipfile

RULES = [
 ("secret-aws", "high", r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
 ("secret-openai", "high", r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}", "OpenAI-style API key"),
 ("secret-anthropic", "high", r"sk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
 ("secret-github", "high", r"gh[pousr]_[A-Za-z0-9]{36}", "GitHub token"),
 ("secret-stripe", "high", r"sk_live_[A-Za-z0-9]{20,}", "Stripe live secret key"),
 ("secret-slack", "high", r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
 ("secret-privkey", "high", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key"),
 ("secret-generic", "medium", r"(?i)(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]", "Hardcoded credential-like assignment"),
 ("eval-use", "high", r"\beval\s*\(", "eval() call: dangerous if input is untrusted or LLM output"),
 ("exec-use", "medium", r"(?<![\w.])exec\s*\(", "exec() call"),
 ("shell-true", "medium", r"shell\s*=\s*True", "subprocess with shell=True"),
 ("os-system", "medium", r"\bos\.system\s*\(", "os.system call"),
 ("pickle-load", "medium", r"pickle\.loads?\s*\(", "pickle load: unsafe on untrusted data"),
 ("yaml-load", "medium", r"yaml\.load\s*\((?![^)]*Loader)", "yaml.load without safe Loader"),
 ("debug-true", "medium", r"(?i)\bdebug\s*[=:]\s*True\b", "Debug mode enabled"),
 ("cors-wildcard", "medium", r"(?i)(?:Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*|origins?\s*=\s*['\"]\*['\"]|cors\(\s*\))", "Wildcard CORS"),
 ("sql-fstring", "high", r"(?i)execute\s*\(\s*f['\"].*(?:select|insert|update|delete)", "SQL built with f-string (injection risk)"),
 ("sql-concat", "medium", r"(?i)(?:select|insert|update|delete)\b[^'\"]*['\"]\s*\+\s*\w", "SQL built by string concatenation"),
 ("dangerous-html", "medium", r"dangerouslySetInnerHTML|\.innerHTML\s*=", "Raw HTML injection (XSS risk)"),
 ("verify-false", "medium", r"verify\s*=\s*False", "TLS verification disabled"),
 ("jwt-none", "high", r"(?i)algorithms?\s*[=:]\s*\[?['\"]none['\"]", "JWT 'none' algorithm"),
 ("supabase-service", "high", r"(?i)service_role", "Supabase service_role key referenced (must never ship to client)"),
]
COMPILED = [(i, s, re.compile(p), d) for i, s, p, d in RULES]
SKIP_DIRS = ("node_modules/", ".git/", "dist/", "build/", "vendor/", ".venv/", "venv/", "__pycache__/")
TEXT_EXT = (".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".rb", ".php", ".java", ".rs",
            ".json", ".yml", ".yaml", ".toml", ".env", ".ini", ".cfg", ".sh", ".html", ".vue", ".svelte", ".tf", ".txt", ".md")
SENSITIVE_FILES = (".env", ".env.local", ".env.production", "id_rsa", "credentials.json", "service-account.json", ".npmrc", ".pypirc")

def fetch_repo_zip(owner, repo, max_bytes=25_000_000):
    for ref in ("HEAD",):
        url = f"https://codeload.github.com/{owner}/{repo}/zip/{ref}"
        req = urllib.request.Request(url, headers={"User-Agent": "vibescan/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("repo archive too large (>25MB)")
        return data

def parse_repo(s):
    s = s.strip().rstrip("/")
    m = re.match(r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/.*)?$", s) or re.match(r"^([\w.-]+)/([\w.-]+)$", s)
    if not m:
        raise ValueError("expected github.com/owner/repo or owner/repo")
    return m.group(1), m.group(2)

def scan_zip(data):
    findings, files, has_ratelimit, has_gitignore_env = [], 0, False, False
    z = zipfile.ZipFile(io.BytesIO(data))
    for info in z.infolist():
        if info.is_dir():
            continue
        path = info.filename.split("/", 1)[-1]
        if any(d in "/" + path for d in ["/" + x for x in SKIP_DIRS]):
            continue
        base = path.rsplit("/", 1)[-1]
        if base in SENSITIVE_FILES or (base.startswith(".env") and not base.endswith((".example", ".sample", ".template"))):
            findings.append({"rule": "sensitive-file", "severity": "high", "file": path, "line": 0, "desc": f"Sensitive file committed: {base}", "snippet": ""})
        if not (path.endswith(TEXT_EXT) or base.startswith(".env") or base == ".gitignore") or info.file_size > 1_000_000:
            continue
        files += 1
        try:
            text = z.read(info).decode("utf-8", "ignore")
        except Exception:
            continue
        if base == ".gitignore" and ".env" in text:
            has_gitignore_env = True
        if re.search(r"(?i)rate.?limit|slowapi|express-rate-limit|throttl", text):
            has_ratelimit = True
        if path.endswith(".md") or path.endswith(".txt"):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if len(line) > 1000:
                continue
            st = line.lstrip()
            is_comment = st.startswith(("//", "#", "*", "/*", "<!--"))
            is_markup = path.endswith((".html", ".vue", ".svelte")) and "<code" in line
            for rid, sev, rx, desc in COMPILED:
                if (is_comment or is_markup) and not rid.startswith("secret"):
                    continue
                if rx.search(line):
                    snip = line.strip()[:160]
                    if rid.startswith("secret"):
                        snip = re.sub(r"([A-Za-z0-9_\-]{4})[A-Za-z0-9_\-]{8,}", r"\1********", snip)
                    findings.append({"rule": rid, "severity": sev, "file": path, "line": n, "desc": desc, "snippet": snip})
    if not has_ratelimit:
        findings.append({"rule": "no-rate-limit", "severity": "low", "file": "", "line": 0, "desc": "No rate limiting found anywhere in the repo", "snippet": ""})
    if not has_gitignore_env:
        findings.append({"rule": "gitignore-env", "severity": "low", "file": ".gitignore", "line": 0, "desc": ".env not listed in .gitignore", "snippet": ""})
    return files, findings

def score(findings):
    w = {"high": 15, "medium": 5, "low": 2}
    return max(0, 100 - sum(w[f["severity"]] for f in findings))

def scan(repo):
    owner, name = parse_repo(repo)
    files, findings = scan_zip(fetch_repo_zip(owner, name))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("high", "medium", "low")}
    return {"repo": f"{owner}/{name}", "files_scanned": files, "score": score(findings), "counts": counts, "findings": findings}

if __name__ == "__main__":
    import sys
    r = scan(sys.argv[1])
    print(json.dumps({k: v for k, v in r.items() if k != "findings"}, indent=1)); print(len(r["findings"]), "findings")
    for f in r["findings"][:15]: print(f["severity"], f["rule"], f["file"], f["line"], f["snippet"][:80])
