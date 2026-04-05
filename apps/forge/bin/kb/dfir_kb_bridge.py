import base64
import json
import math
import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ROOT = SCRIPT_DIR.parent.parent
ROOT = Path(os.environ.get("DFIR_ROOT", str(DEFAULT_ROOT))).resolve()
VAULT = ROOT / "knowledge" / "vault"
LLAMA = os.environ.get("DFIR_LLAMA_URL", "http://127.0.0.1:8080/v1/chat/completions")

WORKSPACE_FOLDER = ""
TEXT_EXTENSIONS = {".md", ".txt", ".json", ".yaml", ".yml", ".rs", ".toml", ".py", ".ps1", ".bat", ".cmd"}


def detect_suite_root() -> Path | None:
    candidates = [
        os.environ.get("STRATA_SUITE_ROOT", ""),
        str(ROOT.parent / "forensic-suite"),
        r"D:\forensic-suite" if os.name == "nt" else "",
        str(Path.home() / "forensic-suite"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser().resolve()
        if (path / "Cargo.toml").exists() and (path / "docs").exists():
            return path
    return None


SUITE_ROOT = detect_suite_root()


@dataclass
class DocumentRecord:
    source: str
    path: str
    title: str
    text: str
    tokens: set[str]


class KnowledgeIndex:
    def __init__(self) -> None:
        self.records: list[DocumentRecord] = []
        self.vault_count = 0
        self.suite_count = 0
        self.embedding_backend = "regex-token-fallback"
        self.embedding_model_name = ""
        self._embedding_model = None
        self._embedding_vectors: list[Any] = []
        self._init_embeddings()

    def _init_embeddings(self) -> None:
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore

            model_name = os.environ.get("DFIR_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
            self._embedding_model = SentenceTransformer(model_name)
            self.embedding_backend = "sentence-transformers"
            self.embedding_model_name = model_name
        except ImportError:  # pragma: no cover - environment dependent
            self.embedding_backend = "regex-token-fallback"
            self._embedding_model = None
            self.embedding_model_name = ""
        except Exception:  # pragma: no cover - environment dependent
            self.embedding_backend = "regex-token-fallback"
            self._embedding_model = None
            self.embedding_model_name = ""

    def rebuild(self) -> None:
        records: list[DocumentRecord] = []
        self.vault_count = 0
        self.suite_count = 0

        if VAULT.exists():
            for path in sorted(VAULT.rglob("*")):
                if path.is_file() and path.suffix.lower() in TEXT_EXTENSIONS:
                    record = self._read_record("vault", path, VAULT)
                    if record:
                        records.append(record)
                        self.vault_count += 1

        if SUITE_ROOT:
            suite_paths: list[Path] = []
            docs_root = SUITE_ROOT / "docs"
            if docs_root.exists():
                suite_paths.extend(p for p in docs_root.rglob("*") if p.is_file() and p.suffix.lower() in TEXT_EXTENSIONS)

            for fixed_path in (SUITE_ROOT / "FEATURES.md", SUITE_ROOT / "SUITE_REALITY_REPORT.md"):
                if fixed_path.exists():
                    suite_paths.append(fixed_path)

            seen_suite: set[Path] = set()
            for path in sorted(suite_paths):
                if path in seen_suite:
                    continue
                seen_suite.add(path)
                record = self._read_record("suite", path, SUITE_ROOT)
                if record:
                    records.append(record)
                    self.suite_count += 1

        self.records = records
        self._embedding_vectors = self._build_embeddings(records)

    def _build_embeddings(self, records: list[DocumentRecord]) -> list[Any]:
        if not self._embedding_model or not records:
            return []
        texts = [f"{record.title}\n{record.text[:4000]}" for record in records]
        try:  # pragma: no cover - depends on external package
            return list(self._embedding_model.encode(texts, normalize_embeddings=False))
        except Exception:
            self.embedding_backend = "regex-token-fallback"
            self._embedding_model = None
            self.embedding_model_name = ""
            return []

    def _read_record(self, source: str, path: Path, root: Path) -> DocumentRecord | None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        rel_path = path.relative_to(root).as_posix()
        title = path.stem.replace("_", " ").replace("-", " ")
        return DocumentRecord(
            source=source,
            path=rel_path,
            title=title,
            text=text,
            tokens=set(tokenize(f"{rel_path} {title} {text[:8000]}")),
        )

        self.search_cache = {}

    def search(self, query: str, limit: int = 6) -> dict[str, Any]:
        q = (query or "").strip()
        if not q:
            return {
                "query": q,
                "results": [],
                "indexed_documents": len(self.records),
                "embedding_backend": self.embedding_backend,
            }

        # Cache check
        cache_key = f"{q}_{limit}"
        if cache_key in self.search_cache:
            return self.search_cache[cache_key]

        results = self._embedding_search(q, limit)
        if not results:
            results = self._token_search(q, limit)

        res = {
            "query": q,
            "results": results,
            "indexed_documents": len(self.records),
            "embedding_backend": self.embedding_backend,
        }
        self.search_cache[cache_key] = res
        return res

    def _embedding_search(self, query: str, limit: int) -> list[dict[str, Any]]:
        if not self._embedding_model or not self._embedding_vectors:
            return []

        try:  # pragma: no cover - depends on external package
            query_vector = self._embedding_model.encode([query], normalize_embeddings=False)[0]
        except Exception:
            return []

        scored: list[tuple[float, DocumentRecord]] = []
        for record, vector in zip(self.records, self._embedding_vectors):
            score = self._cosine_similarity(query_vector, vector)
            if score is None:
                continue
            if score > 0.2:
                scored.append((score, record))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [format_search_result(record, query, score) for score, record in scored[:limit]]

    @staticmethod
    def _cosine_similarity(vec_a: Any, vec_b: Any) -> float | None:
        try:
            dot = 0.0
            norm_a = 0.0
            norm_b = 0.0
            for a, b in zip(vec_a, vec_b):
                fa = float(a)
                fb = float(b)
                dot += fa * fb
                norm_a += fa * fa
                norm_b += fb * fb
            if norm_a <= 0.0 or norm_b <= 0.0:
                return None
            return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))
        except Exception:
            return None

    def _token_search(self, query: str, limit: int) -> list[dict[str, Any]]:
        query_tokens = tokenize(query)
        if not query_tokens:
            return []

        phrase = query.lower()
        scored: list[tuple[float, DocumentRecord]] = []
        for record in self.records:
            haystack = f"{record.path.lower()} {record.title.lower()} {record.text.lower()}"
            score = 0.0
            if phrase in haystack:
                score += 6.0
            if phrase in record.path.lower():
                score += 4.0
            if phrase in record.title.lower():
                score += 4.0

            overlap = sum(1 for token in query_tokens if token in record.tokens)
            score += overlap * 1.5

            for token in query_tokens:
                if token and token in record.text.lower():
                    score += min(3.0, record.text.lower().count(token) * 0.2)

            if score > 0:
                scored.append((score, record))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [format_search_result(record, query, score) for score, record in scored[:limit]]


def tokenize(text: str) -> list[str]:
    return re.findall(r"[a-zA-Z0-9_]{2,}", text.lower())


def extract_snippet(text: str, query: str, radius: int = 3) -> tuple[str, int, int]:
    lines = text.splitlines()
    if not lines:
        return "", 1, 1

    phrase = query.lower()
    query_tokens = tokenize(query)
    for idx, line in enumerate(lines):
        lower = line.lower()
        if phrase in lower or any(token in lower for token in query_tokens):
            start = max(0, idx - radius)
            end = min(len(lines), idx + radius + 1)
            snippet = "\n".join(lines[start:end]).strip()
            return snippet, start + 1, end

    end = min(len(lines), radius * 2 + 1)
    return "\n".join(lines[:end]).strip(), 1, end


def format_search_result(record: DocumentRecord, query: str, score: float) -> dict[str, Any]:
    snippet, line_start, line_end = extract_snippet(record.text, query)
    return {
        "source": record.source,
        "path": record.path,
        "title": record.title,
        "score": round(score, 4),
        "line_start": line_start,
        "line_end": line_end,
        "snippet": snippet,
    }


INDEX = KnowledgeIndex()


def safe_workspace_path(relative_path: str) -> Path:
    if not WORKSPACE_FOLDER:
        raise ValueError("workspace_not_set")

    root = Path(WORKSPACE_FOLDER).resolve()
    full = (root / relative_path).resolve()
    if root != full and root not in full.parents:
        raise ValueError("path_outside_workspace")
    return full


def ocr_image_ps(image_path: str) -> str:
    escaped = image_path.replace("\\", "\\\\")
    ps_script = f"""
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType=WindowsRuntime]
$null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType=WindowsRuntime]
$null = [Windows.Storage.StorageFile, Windows.Foundation, ContentType=WindowsRuntime]

$file = [Windows.Storage.StorageFile]::GetFileFromPathAsync("{escaped}").GetAwaiter().GetResult()
$stream = $file.OpenAsync([Windows.Storage.FileAccessMode]::Read).GetAwaiter().GetResult()
$decoder = [Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream).GetAwaiter().GetResult()
$bitmap = $decoder.GetSoftwareBitmapAsync().GetAwaiter().GetResult()
$ocrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
$result = $ocrEngine.RecognizeAsync($bitmap).GetAwaiter().GetResult()
Write-Output $result.Text
"""
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout.strip() if result.stdout.strip() else result.stderr.strip()
    except Exception as exc:
        return f"OCR Error: {exc}"


def ocr_image_tesseract(image_path: str) -> str:
    tesseract_cmd = ROOT / "bin" / "tesseract" / "tesseract.exe"
    if not tesseract_cmd.exists():
        return "Tesseract not found. Please install Tesseract OCR."

    try:
        result = subprocess.run(
            [str(tesseract_cmd), image_path, "stdout"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout
    except Exception as exc:
        return f"Tesseract Error: {exc}"


def ocr_image(image_path: str) -> str:
    result = ocr_image_ps(image_path)
    if "Error" in result or not result:
        result = ocr_image_tesseract(image_path)
    return result


def build_context_block(query: str, limit: int = 4) -> str:
    response = INDEX.search(query, limit=limit)
    blocks = []
    for result in response["results"]:
        blocks.append(
            f"[SOURCE] {result['source']}\n"
            f"[FILE] {result['path']}\n"
            f"[LINES] {result['line_start']}-{result['line_end']}\n"
            f"{result['snippet']}"
        )
    return "\n\n---\n\n".join(blocks)


def summarize_artifacts(texts: list[str]) -> dict[str, Any]:
    normalized = [str(text).strip() for text in texts if str(text).strip()][:20]
    if not normalized:
        return {"summary": "KB unavailable — 0 artifacts found", "fallback": True}

    prompt_lines = [
        "Summarize these forensic artifacts in 2-3 plain sentences for an investigator:",
        *[f"- {text}" for text in normalized],
    ]
    forward_payload = {
        "model": os.environ.get("DFIR_SUMMARY_MODEL", "phi4-mini"),
        "messages": [
            {
                "role": "system",
                "content": "You are a DFIR assistant. Summarize forensic artifacts clearly and conservatively for an investigator.",
            },
            {"role": "user", "content": "\n".join(prompt_lines)},
        ],
        "temperature": 0.2,
        "stream": False,
    }

    try:
        req_data = json.dumps(forward_payload).encode("utf-8")
        request = Request(LLAMA, data=req_data, headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=10) as response:
            raw = json.loads(response.read().decode("utf-8", errors="replace"))
        summary = (
            raw.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        if summary:
            return {"summary": summary}
    except Exception:
        pass

    return {
        "summary": f"KB unavailable — {len(normalized)} artifacts found",
        "fallback": True,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "StrataKBBridge/1.0"

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Max-Age", "86400")

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw or b"{}")
        except Exception:
            raise ValueError("bad_json")

    def _send(self, code: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(
                200,
                {
                    "status": "ok",
                    "vault_documents": INDEX.vault_count,
                    "suite_documents": INDEX.suite_count,
                    "indexed_documents": len(INDEX.records),
                    "embedding_backend": INDEX.embedding_backend,
                    "embedding_model": INDEX.embedding_model_name or None,
                    "suite_root": str(SUITE_ROOT) if SUITE_ROOT else None,
                },
            )
            return

        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path == "/chat":
            self._handle_chat()
        elif self.path == "/search":
            self._handle_search()
        elif self.path == "/summarize":
            self._handle_summarize()
        elif self.path == "/reindex":
            self._handle_reindex()
        elif self.path == "/ocr":
            self._handle_ocr()
        elif self.path == "/workspace/set_folder":
            self._handle_set_workspace()
        elif self.path == "/workspace/list":
            self._handle_list()
        elif self.path == "/workspace/read":
            self._handle_read()
        elif self.path == "/workspace/write":
            self._handle_write()
        elif self.path == "/workspace/delete":
            self._handle_delete()
        elif self.path == "/workspace/create_dir":
            self._handle_create_dir()
        elif self.path == "/vault/write":
            self._handle_vault_write()
        elif self.path == "/tools/execute":
            self._handle_tool_execution()
        else:
            self._send(404, {"error": "not_found"})

    def _handle_search(self) -> None:
        try:
            payload = self._read_json()
            query = str(payload.get("query", ""))
            limit = max(1, min(int(payload.get("limit", 6)), 20))
            self._send(200, INDEX.search(query, limit))
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_summarize(self) -> None:
        try:
            payload = self._read_json()
            texts = payload.get("texts", [])
            if not isinstance(texts, list):
                self._send(400, {"error": "texts_must_be_list"})
                return
            self._send(200, summarize_artifacts(texts))
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_reindex(self) -> None:
        try:
            INDEX.rebuild()
            self._send(
                200,
                {
                    "status": "ok",
                    "indexed_documents": len(INDEX.records),
                    "vault_documents": INDEX.vault_count,
                    "suite_documents": INDEX.suite_count,
                },
            )
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_set_workspace(self) -> None:
        global WORKSPACE_FOLDER
        try:
            payload = self._read_json()
            workspace = Path(payload.get("path", "")).expanduser().resolve()
            if not workspace.exists():
                self._send(400, {"error": "workspace_not_found"})
                return
            WORKSPACE_FOLDER = str(workspace)
            self._send(200, {"status": "ok", "folder": WORKSPACE_FOLDER})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_list(self) -> None:
        try:
            payload = self._read_json()
            rel_path = str(payload.get("path", "")).strip()
            target = safe_workspace_path(rel_path) if rel_path else Path(WORKSPACE_FOLDER).resolve()
            if not target.exists():
                self._send(400, {"error": "path_not_found"})
                return
            if not target.is_dir():
                self._send(400, {"error": "not_a_directory"})
                return

            entries = []
            for item in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                stat = item.stat()
                entries.append(
                    {
                        "name": item.name,
                        "is_dir": item.is_dir(),
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                    }
                )
            self._send(200, {"entries": entries})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_read(self) -> None:
        try:
            payload = self._read_json()
            target = safe_workspace_path(str(payload.get("path", "")))
            if not target.exists():
                self._send(400, {"error": "path_not_found"})
                return
            if target.is_dir():
                self._send(400, {"error": "cannot_read_directory"})
                return
            content = target.read_text(encoding="utf-8", errors="replace")
            self._send(200, {"path": str(target), "content": content})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_write(self) -> None:
        try:
            payload = self._read_json()
            target = safe_workspace_path(str(payload.get("path", "")))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(str(payload.get("content", "")), encoding="utf-8")
            self._send(200, {"status": "ok", "path": str(target)})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_delete(self) -> None:
        try:
            payload = self._read_json()
            target = safe_workspace_path(str(payload.get("path", "")))
            if not target.exists():
                self._send(400, {"error": "path_not_found"})
                return
            if target.is_dir():
                for child in sorted(target.rglob("*"), reverse=True):
                    if child.is_file():
                        child.unlink()
                    elif child.is_dir():
                        child.rmdir()
                target.rmdir()
            else:
                target.unlink()
            self._send(200, {"status": "ok", "path": str(target)})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_create_dir(self) -> None:
        try:
            payload = self._read_json()
            target = safe_workspace_path(str(payload.get("path", "")))
            target.mkdir(parents=True, exist_ok=True)
            self._send(200, {"status": "ok", "path": str(target)})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_vault_write(self) -> None:
        try:
            payload = self._read_json()
            filename = Path(str(payload.get("filename", "untitled.md"))).name
            if not filename.endswith(".md"):
                filename = f"{filename}.md"
            target = VAULT / filename
            target.write_text(str(payload.get("content", "")), encoding="utf-8")
            INDEX.rebuild()
            self._send(200, {"status": "ok", "path": str(target)})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_tool_execution(self) -> None:
        try:
            payload = self._read_json()
            tool_name = str(payload.get("name", ""))
            args = payload.get("arguments", {})

            if tool_name == "search_knowledge":
                query = str(args.get("query", ""))
                self._send(200, {"output": INDEX.search(query, int(args.get("limit", 4)))})
                return

            if tool_name == "read_file":
                target = safe_workspace_path(str(args.get("path", "")))
                self._send(200, {"output": target.read_text(encoding="utf-8", errors="replace")})
                return

            if tool_name == "write_file":
                target = safe_workspace_path(str(args.get("path", "")))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(str(args.get("content", "")), encoding="utf-8")
                self._send(200, {"output": f"Successfully wrote to {target}"})
                return

            if tool_name == "run_command":
                command = str(args.get("command", "")).strip()
                if not command:
                    self._send(400, {"error": "empty_command"})
                    return
                parsed = shlex.split(command, posix=os.name != "nt")
                proc = subprocess.run(
                    parsed,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=WORKSPACE_FOLDER or str(ROOT),
                )
                self._send(200, {"output": f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"})
                return

            self._send(400, {"error": f"unknown_tool:{tool_name}"})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _handle_ocr(self) -> None:
        try:
            payload = self._read_json()
            image_b64 = payload.get("image", "")
            if not image_b64:
                self._send(400, {"error": "missing_image"})
                return
            image_data = base64.b64decode(image_b64)
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
            return
        except Exception:
            self._send(400, {"error": "invalid_base64"})
            return

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as handle:
            handle.write(image_data)
            temp_path = handle.name

        try:
            text = ocr_image(temp_path)
            self._send(200, {"text": text})
        except Exception as exc:
            self._send(500, {"error": str(exc)})
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def _handle_chat(self) -> None:
        try:
            payload = self._read_json()
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
            return

        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            self._send(400, {"error": "messages_must_be_list"})
            return

        user_text = ""
        for message in reversed(messages):
            if isinstance(message, dict) and message.get("role") == "user":
                user_text = str(message.get("content", ""))
                break

        # SPRINT: Bypass search for short greetings or empty text
        context = ""
        if len(user_text.strip()) > 12:
             context = build_context_block(user_text)
             
        if context:
            injected = {
                "role": "system",
                "content": (
                    "OFFLINE KNOWLEDGE CONTEXT. Cite sources.\n\n" + context
                ),
            }
            messages = [injected] + [m for m in messages if m.get("role") != "system"] + [m for m in messages if m.get("role") == "system"]

        is_stream = payload.get("stream", False)
        forward_payload = {
            "model": payload.get("model", "phi4-mini"),
            "messages": messages,
            "temperature": payload.get("temperature", 0.4),
            "stream": is_stream,
        }

        try:
            req_data = json.dumps(forward_payload).encode("utf-8")
            request = Request(LLAMA, data=req_data, headers={"Content-Type": "application/json"})
            
            with urlopen(request, timeout=120) as response:
                if not is_stream:
                    raw = response.read().decode("utf-8", errors="replace")
                    self._send(200, json.loads(raw))
                else:
                    self.send_response(200)
                    self._cors()
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    # Real-time passthrough for SSE
                    for line in response:
                        if line:
                            self.wfile.write(line)
                            self.wfile.flush()
        except Exception as exc:
            self._send(502, {"error": "llama_bridge_failed", "detail": str(exc)})


def main() -> None:
    VAULT.mkdir(parents=True, exist_ok=True)
    INDEX.rebuild()

    host = os.environ.get("DFIR_KB_HOST", "127.0.0.1")
    port = int(os.environ.get("DFIR_KB_PORT", "8090"))

    print(f"Strata KB Bridge listening on http://{host}:{port}")
    print(f"Vault: {VAULT}")
    print(f"Suite root: {SUITE_ROOT}")
    print(f"Indexed documents: {len(INDEX.records)}")
    print(f"Embedding backend: {INDEX.embedding_backend}")

    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()

