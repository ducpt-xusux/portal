"""Verify the build preserves captured Portal assets and source."""
import argparse
from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.items = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "link"}:
            self.items.append((tag, dict(attrs)))


def verify(web, *, captured_source=False):
    manifest = json.loads((ROOT / "fe-api-staging/portal-extensions.json").read_text())
    capture = json.loads((ROOT / "deploy/portal-local/import-manifest.json").read_text())
    actual = Tags()
    actual.feed((web / "index.html").read_text())
    expected = []
    for entry in manifest["tags"]:
        parser = Tags()
        parser.feed(entry["tag"])
        expected.extend(parser.items)
        for file in (ROOT / entry["path"], web / entry["url"].split("?")[0].lstrip("/")):
            if sha256(file.read_bytes()).hexdigest() != entry["sha256"]:
                raise ValueError(f"Extension changed or omitted: {file}")
    observed = [(tag, attrs) for tag, attrs in actual.items
                if (attrs.get("src") or attrs.get("href") or "").startswith("/assets/n91-")]
    if observed != expected:
        raise ValueError("Extension order or loading attributes differ from capture")
    scripts = [attrs["src"] for tag, attrs in actual.items if tag == "script" and "src" in attrs]
    entries = [attrs for tag, attrs in actual.items
               if tag == "script" and attrs.get("type") == "module"]
    if len(entries) != 1 or not entries[0].get("src", "").startswith("/assets/index-"):
        raise ValueError("Expected one compiled frontend entry")
    first_extension = next(attrs["src"] for tag, attrs in expected if tag == "script")
    if scripts.index(entries[0]["src"]) > scripts.index(first_extension):
        raise ValueError("Frontend entry must precede extension scripts")
    if captured_source:
        prefix = "/home/ubuntu/portal-local/n91-portal-proxy-linux/backend/app/"
        mapping = {
            "/home/ubuntu/portal-local/local_app.py": "deploy/portal-local/local_app.py",
            "/home/ubuntu/portal-local/.n91-proxy-health/collect_proxy_services.py":
                "deploy/portal-local/collect_proxy_services.py",
        }
        for record in capture["runtime_code"]:
            source = record["path"]
            destination = mapping.get(source)
            if source.startswith(prefix):
                destination = "backend/app/" + source.removeprefix(prefix)
            if source.startswith("/opt/db-firewall/"):
                destination = "components/p17-worker/" + Path(source).name
            if destination and sha256((ROOT / destination).read_bytes().replace(b"\r\n", b"\n")).hexdigest() != record["normalized_sha256"]:
                raise ValueError(f"Imported source differs: {destination}")
        for entry in capture["base_frontend_assets"]:
            path = web / entry["url"].lstrip("/")
            if sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
                raise ValueError(f"Base frontend differs from live capture: {path}")
    print(f"IMPORT_VERIFY_PASS extensions={len(expected)} captured_source={captured_source}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--web", required=True, type=Path)
    parser.add_argument("--captured-source", action="store_true")
    args = parser.parse_args()
    verify(args.web.resolve(), captured_source=args.captured_source)
