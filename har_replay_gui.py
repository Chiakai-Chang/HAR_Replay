# -*- coding: utf-8 -*-
"""
HAR Replay Pro (整合版) — Evidence-Grade Replayer
Version: 2025.09.03-pro1
整合作者: Gemini (Google AI)
原始作者: Chiakai (GUI), ChatGPT (Backend)

本版本整合了以下兩份腳本的優點：
- har_replay_gui.py: 友善的 Tkinter GUI、取證教學、剪貼簿工具。
- har_replay_gui_v2_gui.py: 強健的後端邏輯，包含內容雜湊、BS4解析、SPA偵測與證據匯出。

特色：
- 專業 GUI 介面，內建現場取證 SOP 教學。
- 基於內容雜湊 (SHA256) 管理資源，無重複儲存，符合取證精神。
- 使用 BeautifulSoup (bs4) 解析 HTML，大幅提高資源路徑改寫的準確度。
- 偵測 SPA 空殼頁面，並在合成時給予提示。
- 一鍵匯出為標準化的「證據包」(Evidence Bundle)，包含報告與雜湊值。
- 清單頁顯示每個時間點的「離線可見度」與「JS 命中率」，評估 HAR 完整性。
"""
import os, sys, json, base64, re, hashlib, html, mimetypes, datetime as dt, threading, webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote, unquote, urlunparse
from pathlib import Path
import argparse

# --- 整合 v1 的相依性 ---
import gzip, zlib
try:
    import brotli as _brotli
except ImportError:
    _brotli = None

# --- 版本與作者資訊 ---
__version__ = "2025.09.03-pro1"
#__author__  = "Gemini (Integrator), Chiakai (GUI), ChatGPT (Backend)"
__author__  = "Chiakai"
UNIT_STR = "臺中市政府警察局刑事警察大隊科技犯罪偵查隊"


# ---------- Optional deps & Timezone (整合自 v2) ----------
try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False
    print("[警告] 未安裝 `beautifulsoup4`，HTML 解析將退回正則表達式模式，還原度可能下降。")
    print("[提示] 請執行: pip install beautifulsoup4")

try:
    from zoneinfo import ZoneInfo
    _TZ_TAIPEI = ZoneInfo("Asia/Taipei")
except ImportError:
    _TZ_TAIPEI = dt.timezone(dt.timedelta(hours=8))

# ---------- 資源路徑 (for PyInstaller, from v1) ----------
def resource_path(relative_path: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)

APP_ICON_CANDIDATES = ["app.ico", "app.png"]  # 視窗 icon 任一存在就用
BANNER_FILE = "banner.png"                     # GUI 橫幅圖（選填）

# ---------- 通用工具函式 (整合 v1 & v2) ----------
def utc_to_taipei(iso_str: str) -> str:
    if not iso_str: return ""
    try:
        s = iso_str.replace("Z", "+00:00")
        d = dt.datetime.fromisoformat(s)
        if d.tzinfo is None: d = d.replace(tzinfo=dt.timezone.utc)
        return d.astimezone(_TZ_TAIPEI).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso_str

def iso_norm(iso_str: str) -> str:
    try:
        s = iso_str.replace("Z", "+00:00")
        d = dt.datetime.fromisoformat(s)
        if d.tzinfo is None: d = d.replace(tzinfo=dt.timezone.utc)
        return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return iso_str

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def md5_bytes(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()

def guess_mime(url_path: str, fallback="application/octet-stream") -> str:
    mime, _ = mimetypes.guess_type(url_path)
    # 修正 .js 常被誤判的問題 (from v1)
    if (url_path or "").lower().endswith('.js'):
        return 'application/javascript'
    return mime or fallback

def ensure_text(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return b.decode("latin-1", errors="replace")

CSS_URL_RE = re.compile(r'url\((?P<q>["\']?)(?P<path>[^)]+?)(?P=q)\)', re.IGNORECASE)
def replace_css_urls(css_text: str, repl_func):
    def _repl(m):
        raw = m.group("path").strip()
        # 避免處理 data: URIs
        if raw.lower().startswith('data:'):
            return f'url({m.group("q")}{raw}{m.group("q")})'
        return f'url("{repl_func(raw)}")'
    return CSS_URL_RE.sub(_repl, css_text or "")

_ABS_RE = re.compile(r"^(?i:https?:)?//")
def _is_data_uri(u: str) -> bool: return (u or "").strip().lower().startswith("data:")
def _join_url(base_url: str, ref: str) -> str:
    if not ref: return ref
    if _ABS_RE.match(ref) or ref.startswith("/"): return ref
    try:
        bu = urlparse(base_url)
        base_path = bu.path
        if not base_path.endswith('/'):
            base_dir = os.path.dirname(base_path)
        else:
            base_dir = base_path
        if not base_dir.endswith('/'):
            base_dir += '/'
        
        new_path = os.path.normpath(base_dir + ref)
        return urlunparse((bu.scheme, bu.netloc, new_path, "", "", ""))
    except Exception:
        return ref
        
# ---------- HAR Index (核心類別 from v2, 整合 v1 的解壓縮邏輯) ----------
class HarIndex:
    def __init__(self, har_dict: dict):
        self.har = har_dict
        log = har_dict.get("log", {})
        self.entries = log.get("entries", [])
        self.pages = log.get("pages", [])
        self.by_url = {}
        self.html_entries = []  # (iso, entry)
        self.res_payload = {}
        self.res_meta = {}
        self._build()

    def _maybe_decompress(self, raw: bytes, headers: dict) -> bytes:
        enc = (headers or {}).get('content-encoding', '').lower()
        if not raw: return raw
        try:
            if 'gzip' in enc: return gzip.decompress(raw)
            if 'deflate' in enc: return zlib.decompress(raw)
            if 'br' in enc and _brotli: return _brotli.decompress(raw)
        except Exception: pass
        return raw

    def _entry_bytes(self, e) -> bytes | None:
        try:
            res = e.get("response", {})
            content = res.get("content", {})
            if "text" not in content: return None

            text = content.get("text") or ""
            encoding = content.get("encoding")
            
            if encoding == "base64":
                raw = base64.b64decode(text)
            else:
                raw = text.encode("utf-8", errors="replace")

            headers = {h.get('name','').lower(): h.get('value','') for h in res.get("headers", [])}
            return self._maybe_decompress(raw, headers)
        except Exception:
            return None

    def _build(self):
        for e in self.entries:
            req = e.get("request", {})
            res = e.get("response", {})
            url = req.get("url", "")
            if not url: continue

            self.by_url.setdefault(url, []).append(e)
            b = self._entry_bytes(e)
            
            if b is not None:
                rid = sha256_bytes(b)[:16]
                if rid not in self.res_payload:
                    self.res_payload[rid] = b
                    content = res.get("content", {})
                    self.res_meta[rid] = {
                        "url": url,
                        "mime": content.get("mimeType") or guess_mime(url),
                        "status": res.get("status"),
                        "startedDateTime": e.get("startedDateTime"),
                        "pageref": e.get("pageref"),
                        "size": len(b),
                        "sha256": sha256_bytes(b),
                        "md5": md5_bytes(b),
                    }
            
            mime = (res.get("content", {}).get("mimeType") or "").lower()
            if "text/html" in mime and req.get('method', 'GET').upper() == 'GET':
                self.html_entries.append((iso_norm(e.get("startedDateTime") or ""), e))
        
        self.html_entries.sort(key=lambda t: t[0], reverse=True)

    def list_pages(self):
        out = []
        if not self.pages:
            times = [e.get("startedDateTime") for e in self.entries if e.get("startedDateTime")]
            started = min(times) if times else None
            out.append({"id": "page_0", "title": "Default Page", "startedDateTime": started}); return out
        for p in self.pages:
            out.append({"id": p.get("id"), "title": p.get("title"), "startedDateTime": p.get("startedDateTime")})
        return out

    def best_home_html_entry(self, page_id: str | None):
        cands = []
        entries = [e for e in self.entries if (page_id is None or e.get("pageref")==page_id)]
        for e in entries:
            res = e.get("response", {})
            content = res.get("content", {})
            mime = (content.get("mimeType") or "").lower()
            if "text/html" in mime:
                b = self._entry_bytes(e); size = len(b) if b else 0
                ok = res.get("status") in (200, 304)
                cands.append((ok, size, e))
        if not cands: return None
        cands.sort(key=lambda x:(x[0], x[1]), reverse=True)
        return cands[0][2]

    def html_entry_by_ts(self, ts_iso: str):
        if not self.html_entries: return None
        # 精確匹配
        for ts, e in self.html_entries:
            if ts == ts_iso: return e
        # 若無，找第一個比它早的
        earlier = [e for ts, e in self.html_entries if ts <= ts_iso]
        return earlier[0] if earlier else self.html_entries[-1][1]

    def payload_for_url(self, url: str):
        lst = self.by_url.get(url) or []
        # 從最新的請求開始找
        for e in reversed(lst):
            b = self._entry_bytes(e)
            if b is not None:
                rid = sha256_bytes(b)[:16]
                return rid, b, self.res_meta.get(rid)
        return None, None, None

# ---------- Composer (核心類別 from v2) ----------
class Composer:
    def __init__(self, har: HarIndex, snapshot_html: str | None = None):
        self.har = har
        self.snapshot_html = snapshot_html
        self.url_to_resid = {}
        for url in self.har.by_url.keys():
            rid, b, meta = self.har.payload_for_url(url)
            if rid: self.url_to_resid[url] = rid

    def _map(self, u: str, base_url: str, ext: str, stats):
        if not u or _is_data_uri(u): return u
        full = _join_url(base_url, u)
        stats["total"] += 1
        if full.lower().endswith('.js'): stats["js_total"] += 1
            
        rid = self.url_to_resid.get(full)
        if rid:
            stats["hits"] += 1
            if full.lower().endswith('.js'): stats["js_hits"] += 1
            return f"/__res?id={rid}"
        
        stats["missing"].append(full)
        return full if ext=="on" else f"/__missing?url={quote(full)}"

    def _rewrite_html(self, html_text: str, base_url: str, ext: str):
        stats = {"total":0, "hits":0, "missing":[], "js_total": 0, "js_hits": 0}
        if not _HAS_BS4:
            # Fallback regex mode
            out = re.sub(r'(?P<attr>\b(?:src|href)=)(["\'])(?P<u>[^"\']+)\2',
                         lambda m: f'{m.group("attr")}"{self._map(m.group("u"), base_url, ext, stats)}"',
                         html_text, flags=re.IGNORECASE)
            out = replace_css_urls(out, lambda p: self._map(p.strip(), base_url, ext, stats))
            return out, stats
        
        # Preferred BeautifulSoup mode
        soup = BeautifulSoup(html_text, "html.parser")
        for tag, attr in [("img","src"),("script","src"),("link","href"),("iframe","src"), ("source", "src"), ("video", "poster")]:
            for el in soup.find_all(tag):
                u = el.get(attr)
                if u: el[attr] = self._map(u, base_url, ext, stats)
        for el in soup.find_all("style"):
            if el.string and "url(" in el.string:
                el.string = replace_css_urls(el.string, lambda p:self._map(p, base_url, ext, stats))
        for el in soup.find_all(True, style=True):
            st = el.get("style")
            if st and "url(" in st:
                el["style"] = replace_css_urls(st, lambda p:self._map(p, base_url, ext, stats))
        return str(soup), stats

    def _is_spa_shell(self, html_text: str) -> bool:
        bt = html_text.lower()
        m = re.search(r"<body[^>]*>(.*)</body>", bt, flags=re.DOTALL)
        if not m: return False
        inner = m.group(1)
        textish = re.sub(r"<[^>]+>", "", inner).strip()
        scripts = len(re.findall(r"<script\b", inner, flags=re.IGNORECASE))
        return (len(textish)<50) and (scripts>=1)

    def _err_page(self) -> bytes:
        html_err = """<!doctype html><html><head><meta charset="utf-8">
<title>回放錯誤</title><style>body{font-family:ui-sans-serif,system-ui;max-width:780px;margin:28px auto;padding:0 16px;color:#222}.callout{background:#fff4cd;border:1px solid #ffe39a;border-radius:8px;padding:14px 16px}</style></head>
<body><h1>無法回放本頁</h1>
<div class="callout"><p><strong>原因：</strong>主頁 HTML 缺失或為 SPA 空殼頁。</p>
<ul><li>請提供 DOM Snapshot（基底快照）。</li>
<li>或用「外聯補資源模式」。</li>
<li>或重新蒐集 HAR（停用快取 + Save all as HAR with content）。</li></ul>
</div></body></html>"""
        return html_err.encode("utf-8")

    def _banner(self, html_text: str, msg: str) -> str:
        inj = f"""<div style="position:fixed;left:0;right:0;top:0;background:#fff4cd;border-bottom:1px solid #ffe39a;color:#7a5a00;padding:8px 12px;z-index:99999;font-family:ui-sans-serif,system-ui"><strong>提示</strong>：{html.escape(msg)}</div>"""
        return re.sub("</body>", inj+"</body>", html_text, flags=re.IGNORECASE) if "</body>" in html_text.lower() else inj+html_text

    def _compose(self, base_html, base_url, ext="off"):
        if not (base_html and base_html.strip()): return self._err_page(), {"total":0,"hits":0,"missing":[]}
        out, stats = self._rewrite_html(base_html, base_url, ext)
        if (not self.snapshot_html) and self._is_spa_shell(base_html):
            out = self._banner(out, "偵測到此頁面可能為 SPA 空殼頁，建議提供 DOM Snapshot（基底快照）以獲取最佳還原效果。")
        return out.encode("utf-8"), stats
        
    def compose_final(self, page_id: str|None, ext="off"):
        base_html, base_url = None, ""
        best_entry = self.har.best_home_html_entry(page_id)
        
        if self.snapshot_html:
            base_html = self.snapshot_html
            base_url = best_entry.get("request",{}).get("url","") if best_entry else ""
        elif best_entry:
            rid, b, _ = self.har.payload_for_url(best_entry.get("request",{}).get("url",""))
            base_html = ensure_text(b or b"")
            base_url = best_entry.get("request",{}).get("url","")
            
        return self._compose(base_html, base_url, ext)

    def compose_by_ts(self, ts_iso: str, ext="off"):
        base_html, base_url = None, ""
        entry = self.har.html_entry_by_ts(ts_iso)

        if self.snapshot_html:
            base_html = self.snapshot_html
            base_url = entry.get("request",{}).get("url","") if entry else ""
        elif entry:
            rid, b, _ = self.har.payload_for_url(entry.get("request",{}).get("url",""))
            base_html = ensure_text(b or b"")
            base_url = entry.get("request",{}).get("url","")
            
        return self._compose(base_html, base_url, ext)


# ---------- Exporter (核心類別 from v2) ----------
class Exporter:
    def __init__(self, har: HarIndex, composer: Composer, out_dir: str):
        self.har = har; self.composer = composer; self.out_dir = out_dir

    def run(self, mode: str, ts_iso: str|None=None, page_id: str|None=None):
        os.makedirs(self.out_dir, exist_ok=True)
        res_dir = os.path.join(self.out_dir, "resources"); os.makedirs(res_dir, exist_ok=True)
        for rid,b in self.har.res_payload.items():
            with open(os.path.join(res_dir, rid), "wb") as f: f.write(b)
        
        if ts_iso:
            html_bytes, stats = self.composer.compose_by_ts(ts_iso, ext=mode)
        else:
            html_bytes, stats = self.composer.compose_final(page_id, ext=mode)
        
        snap_path = os.path.join(self.out_dir, "page_snapshot.html")
        with open(snap_path, "wb") as f: f.write(html_bytes)
        
        manifest = {
            "generated_at": dt.datetime.utcnow().isoformat()+"Z",
            "replay_version": __version__,
            "mode": "online-augment" if mode=="on" else "offline",
            "ts_iso_utc": ts_iso, "page_id": page_id,
            "final_snapshot": {"path":"page_snapshot.html","sha256":sha256_bytes(html_bytes),"md5":md5_bytes(html_bytes)},
            "resources": list(self.har.res_meta.values()),
            "missing_resources": stats.get("missing", []),
        }
        with open(os.path.join(self.out_dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        
        with open(os.path.join(self.out_dir, "hashes_sha256.txt"), "w", encoding="utf-8") as f:
            f.write(f"{manifest['final_snapshot']['sha256']}  page_snapshot.html\n")
            for rid in self.har.res_payload.keys():
                meta = self.har.res_meta.get(rid, {})
                f.write(f"{meta.get('sha256')}  resources/{rid}\n")
        
        report = self._report_html(manifest)
        with open(os.path.join(self.out_dir, "report.html"), "w", encoding="utf-8") as f: f.write(report)
        
        with open(os.path.join(self.out_dir, "NOTE.txt"), "w", encoding="utf-8") as f:
            f.write("此為自動化產生的證據包。\n若需手動截圖或錄影，請開啟 page_snapshot.html 進行操作。\n")
        
        return self.out_dir

    def _report_html(self, m: dict) -> str:
        rows = []
        for meta in sorted(m['resources'], key=lambda x: x.get('startedDateTime', '')):
            rows.append("<tr>"
                        f"<td>{html.escape(meta.get('mime') or '')}</td>"
                        f"<td style='word-break:break-all'><code>{html.escape(meta.get('url') or '')}</code></td>"
                        f"<td>{meta.get('status')}</td>"
                        f"<td>{meta.get('size')}</td>"
                        f"<td><code>{html.escape(meta.get('sha256',''))}</code></td>"
                        "</tr>")
        miss = "".join(f"<li><code>{html.escape(u)}</code></li>" for u in m.get("missing_resources", []))
        return f"""<!doctype html><html><head><meta charset="utf-8"><title>Evidence Report</title>
<style>body{{font-family:ui-sans-serif,system-ui;max-width:1060px;margin:28px auto;padding:0 16px;color:#222}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;border-bottom:1px solid #eee;padding:8px}}code{{background:#eef2f6;padding:2px 4px;border-radius:4px}}</style></head>
<body><h1>Evidence Report</h1>
<p><strong>Generated at (UTC)</strong> {html.escape(m['generated_at'])} ｜ <strong>Mode</strong> {html.escape(m['mode'])}</p>
<p><strong>Timestamp (UTC)</strong> {html.escape(m.get('ts_iso_utc') or 'Latest (Final Composition)')}</p>
<h2>Missing Resources ({len(m.get('missing_resources',[]))})</h2><ul>{miss or "<li>None</li>"}</ul>
<h2>Archived Resources ({len(m.get('resources',[]))})</h2><table><thead><tr><th>MIME</th><th>Original URL</th><th>Status</th><th>Size (Bytes)</th><th>SHA256</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
</body></html>"""

# ---------- Web UI (整合 v1 & v2) ----------
LIST_TMPL = """<!doctype html><html><head><meta charset="utf-8">
<title>HAR 回放清單</title>
<style>
 body { font-family: -apple-system, BlinkMacSystemFont, "Noto Sans CJK TC", "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color:#222; }
 .wrap { max-width: 1080px; margin: 28px auto; padding: 0 16px; }
 .subtle { color:#666; margin: 0 0 18px; }
 .callout { background:#f6f8fa; border:1px solid #eaecef; padding:14px 16px; border-radius:8px; margin:18px 0; }
 .btn { display:inline-block; padding:8px 14px; border-radius:6px; text-decoration:none; border:1px solid #d0d7de; background:#fff; color:#0969da; }
 .btn.primary { background:#0969da; color:#fff; border-color:#0969da; }
 .btn.small { padding:6px 10px; font-size: 12px; }
 table { width:100%; border-collapse:collapse; table-layout: fixed; }
 thead th { text-align:left; font-weight:600; color:#444; border-bottom:1px solid #eaecef; padding:8px 10px; }
 tbody td { vertical-align:top; border-bottom:1px solid #f0f2f4; padding:10px; }
 code { background:#eef2f6; padding:2px 6px; border-radius:4px; }
 .col-time { width: 170px; white-space:nowrap; }
 .col-url  { width: 520px; overflow-wrap:anywhere; word-break:break-all; }
 .col-score { width: 110px; }
 .col-actions { width: 240px; }
 .badge { display:inline-block; min-width:48px; text-align:center; padding:2px 8px; border-radius:12px; font-size:12px; }
 .badge.ok { background:#daf5d8; color:#1b5e20; border:1px solid #b7e4b3; }
 .badge.warn { background:#fff4cd; color:#7a5a00; border:1px solid #ffe39a; }
 .badge.bad { background:#ffe2e0; color:#7f1d1d; border:1px solid #ffb3ad; }
 .dupe { color:#7a5a00; font-size:12px; }
 .footer { color:#555; margin-top: 18px; text-align:right; }
</style></head>
<body><div class="wrap">
  <h1>HAR 回放清單</h1>
  <p class="subtle">版本 __VER__ ｜ 時區 <strong>台灣（UTC+8）</strong></p>
  <div class="callout">
    <p style="margin:0 0 6px;"><strong>最終合成 (Final Composition):</strong> 以「__HOME__」為主頁，整合 HAR 中所有資源，呈現最完整的最終狀態。</p>
    __BASE_HINT__
    <p style="margin:6px 0 0;">
      <a class="btn primary" target="_blank" rel="noopener" href="/__compose?view=final&ext=on">最終合成（外聯補資源）</a>
      <a class="btn" target="_blank" rel="noopener" href="/__compose?view=final&ext=off">最終合成（純本機）</a>
      <a class="btn" target="_blank" rel="noopener" href="/__debug">偵錯資訊</a>
    </p>
  </div>
  <h3>依時間點預覽 (新 → 舊)</h3>
  <table><thead><tr>
    <th class="col-time">時間 (UTC+8)</th>
    <th class="col-url">路徑 (path+query)</th>
    <th class="col-score">離線可見度</th>
    <th class="col-score">JS 命中率</th>
    <th class="col-actions">預覽</th>
  </tr></thead><tbody>__ROWS__</tbody></table>

  <p class="footer">臺中市政府警察局刑事警察大隊科技犯罪偵查隊</p>
</div></body></html>
"""

class AppState:
    def __init__(self, har_path: str, snapshot_path: str|None):
        with open(har_path, "rb") as f: har_dict = json.load(f)
        self.har = HarIndex(har_dict)
        self.snapshot_html = None
        self.snapshot_path = snapshot_path
        if snapshot_path and os.path.exists(snapshot_path):
            self.snapshot_html = Path(snapshot_path).read_text(encoding="utf-8", errors="ignore")
        self.composer = Composer(self.har, self.snapshot_html)

    def list_rows(self):
        rows = []
        seen_paths = set()
        for ts_iso, e in self.har.html_entries:
            url = e.get("request",{}).get("url","")
            u = urlparse(url); path = u.path + (("?"+u.query) if u.query else "")
            local_time = utc_to_taipei(ts_iso)
            
            # 使用 composer 來評分，確保邏輯一致
            _, stats = self.composer.compose_by_ts(ts_iso, ext="off")
            
            total, hits = stats.get("total",0), stats.get("hits",0)
            js_total, js_hits = stats.get("js_total", 0), stats.get("js_hits", 0)
            
            vis_ratio = round(hits * 100 / max(1, total)) if total > 0 else 100
            js_ratio = round(js_hits * 100 / max(1, js_total)) if js_total > 0 else 100
            
            vis_badge = "ok" if vis_ratio >= 80 else ("warn" if vis_ratio >= 50 else "bad")
            js_badge = "ok" if js_ratio >= 80 else ("warn" if js_ratio >= 50 else "bad")
            
            dupe_html = " <span class='dupe'>(重複路徑)</span>" if path in seen_paths else ""
            seen_paths.add(path)
            
            rows.append(f"""<tr><td><code>{html.escape(local_time)}</code></td>
                        <td><code title='{html.escape(path)}'>{html.escape(path[:80])}{'...' if len(path)>80 else ''}</code>{dupe_html}</td>
                        <td title="資源總數: {total}, 命中: {hits}"><span class='badge {vis_badge}'>{vis_ratio}%</span></td>
                        <td title="JS總數: {js_total}, 命中: {js_hits}"><span class='badge {js_badge}'>{js_ratio}%</span></td>
                        <td><a class='btn small primary' target='_blank' rel='noopener' href='/__compose?view=time&ts={quote(ts_iso)}&ext=on'>外聯補資源</a>
                            <a class='btn small' target='_blank' rel='noopener' href='/__compose?view=time&ts={quote(ts_iso)}&ext=off'>純本機</a></td></tr>""")
        
        if not rows:
            rows.append("<tr><td colspan='5' style='color:#666;text-align:center;padding:18px 0'>此 HAR 未發現 text/html 回應，強烈建議提供 DOM Snapshot (基底快照)。</td></tr>")
        
        home_entry = self.har.best_home_html_entry(None)
        home_path = urlparse(home_entry.get('request',{}).get('url','') if home_entry else "").path or "(未檢出)"
        return "\n".join(rows), home_path

# ---------- HTTP Server (Handler from v2) ----------
class Handler(BaseHTTPRequestHandler):
    state: AppState = None  # type: ignore
    
    def log_message(self, fmt, *args): pass
    
    def _w(self, code:int, body:bytes, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        # 移除有害標頭 (from v1)
        self.send_header("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path)
        qs = parse_qs(p.query)

        if p.path in ("/","/__list"):
            rows, home = self.state.list_rows()
            base_hint_html = ""
            if self.state.snapshot_path:
                base_hint_html = f"<p style='margin:8px 0 0;color:#0a7;'>已套用基底快照：<code>{html.escape(self.state.snapshot_path)}</code></p>"

            page_html = LIST_TMPL.replace("__ROWS__", rows).replace("__HOME__", html.escape(home)) \
                                 .replace("__VER__", __version__).replace("__BASE_HINT__", base_hint_html)
            self._w(200, page_html.encode("utf-8")); return

        if p.path=="/__debug":
            info = {
                "version": __version__,
                "har_pages": len(self.state.har.pages),
                "har_entries": len(self.state.har.entries),
                "archived_resources": len(self.state.har.res_payload),
                "snapshot_path": self.state.snapshot_path,
                "bs4_enabled": _HAS_BS4
            }
            body = f"<!doctype html><html><head><title>Debug</title></head><body><pre>{html.escape(json.dumps(info, indent=2))}</pre></body></html>"
            self._w(200, body.encode("utf-8")); return

        if p.path=="/__compose":
            view = (qs.get("view",["final"])[0]).lower()
            ext=(qs.get("ext",["off"])[0]).lower()
            if view=="final":
                body, _ = self.state.composer.compose_final(page_id=None, ext=ext)
            else:
                ts = iso_norm(qs.get("ts",[""])[0])
                body, _ = self.state.composer.compose_by_ts(ts, ext=ext)
            self._w(200, body); return

        if p.path=="/__res":
            rid = qs.get("id",[""])[0]
            b = self.state.har.res_payload.get(rid)
            meta = self.state.har.res_meta.get(rid,{})
            if b is None: self._w(404, b"Not Found", "text/plain; charset=utf-8"); return
            ctype = meta.get("mime") or guess_mime(meta.get("url", ""))
            self._w(200, b, ctype); return

        if p.path=="/__missing":
            u = html.escape(unquote(qs.get("url",[""])[0]))
            body = f"""<!doctype html><html><head><meta charset='utf-8'><title>缺失資源</title>
<style>body{{font-family:ui-sans-serif,system-ui;max-width:720px;margin:28px auto;padding:0 16px;color:#222}}.callout{{background:#ffe2e0;border:1px solid #ffb3ad;border-radius:8px;padding:14px 16px}}</style></head>
<body><h1>資源缺失 (離線模式)</h1><div class='callout'><p>此資源未包含於 HAR：</p><p><code style='word-break:break-all'>{u}</code></p><p>可切換「外聯補資源模式」或重新蒐集完整 HAR。</p></div></body></html>"""
            self._w(200, body.encode("utf-8")); return
        
        self._w(404, b"Not Found", "text/plain; charset=utf-8")

# ---------- Server Runner ----------
def run_server(har_path: str, snapshot_path: str|None, port=8000, on_ready=None, on_error=None):
    try:
        app_state = AppState(har_path, snapshot_path)
        Handler.state = app_state
        httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        
        def _serve():
            if on_ready: on_ready(f"http://127.0.0.1:{port}")
            httpd.serve_forever()

        th = threading.Thread(target=_serve, daemon=True)
        th.start()
        return httpd, th
    except Exception as e:
        if on_error: on_error(str(e))
        else: print(f"[錯誤] 伺服器啟動失敗: {e}")
        return None, None

# ---------- Desktop GUI (整合 v1 & v2) ----------
def start_gui(args):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    try:
        from tkinter import PhotoImage
    except ImportError:
        PhotoImage = None # type: ignore

    DOM_SNIPPET = 'copy(document.documentElement.outerHTML);'

    class App(tk.Tk):
        def __init__(self, args):
            super().__init__()
            self.title(f"HAR Replay Pro {__version__}  —  {UNIT_STR} —  by {__author__}")
            self.geometry("780x680")
            self.resizable(False, False)
            
            self.srv = {"httpd": None, "th": None, "port": args.port}

            # --- Icon and Banner (from v1) ---
            for cand in APP_ICON_CANDIDATES:
                p = resource_path(cand)
                if os.path.isfile(p):
                    try:
                        if p.lower().endswith(".ico"):
                            self.iconbitmap(default=p)
                        else:
                            self.iconphoto(True, PhotoImage(file=p))
                        break
                    except Exception:
                        pass

            top = ttk.Frame(self); top.pack(fill="x", padx=12, pady=(10,4))
            
            banner_path = resource_path(BANNER_FILE)
            self._banner_img = None
            if os.path.isfile(banner_path):
                try:
                    self._banner_img = PhotoImage(file=banner_path)
                    ttk.Label(top, image=self._banner_img).pack(anchor="c", pady=(6,10))
                except Exception:
                    pass
                
            intro = ("HAR 回放與證據產製工具\n"
                     "1) 選擇 .har 檔 → 2) (強烈建議) 提供「基底快照」→ 3) 啟動伺服器\n"
                     "   點「最終合成」或時間點預覽，即可重現網頁畫面。")
            ttk.Label(top, text=intro, justify='left').pack(anchor="w")
            
            # --- 檔案/埠號 (Layout from v1) ---
            frm1 = ttk.LabelFrame(self, text="輸入檔案"); frm1.pack(fill="x", padx=12, pady=6)
            
            self.har_var = tk.StringVar(value=args.har or "")
            self.snap_var = tk.StringVar(value=args.snapshot or "")
            
            ttk.Label(frm1, text="HAR 檔案:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
            ttk.Entry(frm1, textvariable=self.har_var).grid(row=0, column=1, sticky="ew", padx=6)
            ttk.Button(frm1, text="選擇…", command=self.choose_har).grid(row=0, column=2, sticky="w", padx=6)
            
            ttk.Label(frm1, text="基底快照 (DOM):").grid(row=1, column=0, sticky="w", padx=6, pady=4)
            ttk.Entry(frm1, textvariable=self.snap_var).grid(row=1, column=1, sticky="ew", padx=6)
            ttk.Button(frm1, text="選擇…", command=self.choose_snap).grid(row=1, column=2, sticky="w", padx=6)
            frm1.grid_columnconfigure(1, weight=1)

            # --- 取證工具 (from v1) ---
            tools = ttk.LabelFrame(self, text="現場取證工具"); tools.pack(fill="x", padx=12, pady=6)
            ttk.Button(tools, text="取證教學", command=self.open_forensic_tips).pack(side="left", padx=6, pady=4)
            ttk.Button(tools, text="複製 DOM 指令", command=lambda: self.copy_to_clipboard(DOM_SNIPPET)).pack(side="left", padx=6)
            ttk.Button(tools, text="從剪貼簿存成 HTML…", command=self.save_clipboard_to_html).pack(side="left", padx=6)

            # --- 伺服器控制 ---
            srv_frm = ttk.LabelFrame(self, text="本機回放伺服器"); srv_frm.pack(fill="x", padx=12, pady=6)
            ttk.Label(srv_frm, text="Port:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
            self.port_var = tk.IntVar(value=args.port or 8000)
            ttk.Entry(srv_frm, textvariable=self.port_var, width=10).grid(row=0, column=1, sticky="w", padx=6)
            
            self.btn_start = ttk.Button(srv_frm, text="啟動伺服器", command=self.start_server)
            self.btn_start.grid(row=0, column=2, padx=6)
            self.btn_stop = ttk.Button(srv_frm, text="停止伺服器", command=self.stop_server, state="disabled")
            self.btn_stop.grid(row=0, column=3, padx=6)
            self.btn_open = ttk.Button(srv_frm, text="開啟清單頁", command=lambda: webbrowser.open(f"http://127.0.0.1:{self.port_var.get()}/"), state="disabled")
            self.btn_open.grid(row=0, column=4, padx=6)
            
            # --- 作者 / 單位 / 版本 資訊列（靠右，風格與舊版一致） ---
            meta = ttk.Frame(self)
            meta.pack(fill="x", padx=12, pady=(2, 0))
            ttk.Label(
                meta,
                text=f"{UNIT_STR}  ｜   作者：{__author__}  ｜   版本：{__version__}",
                foreground="#555"
            ).pack(side="right")
            
            # --- 證據匯出 (from v2) ---
            exp = ttk.LabelFrame(self, text="匯出證據包"); exp.pack(fill="x", padx=12, pady=6)
            self.mode_var = tk.StringVar(value="off")
            ttk.Radiobutton(exp, text="純離線 (Offline)", variable=self.mode_var, value="off").grid(row=0, column=0, sticky="w", padx=6, pady=4)
            ttk.Radiobutton(exp, text="外聯註記 (Online Augment)", variable=self.mode_var, value="on").grid(row=0, column=1, sticky="w", padx=6)

            ttk.Label(exp, text="時間戳 (ISO, 可空):").grid(row=1, column=0, sticky="w", padx=6, pady=4)
            self.ts_var = tk.StringVar()
            ttk.Entry(exp, textvariable=self.ts_var, width=30).grid(row=1, column=1, sticky="w", padx=6)
            ttk.Button(exp, text="匯出", command=self.do_export).grid(row=1, column=2, padx=6)

            # --- 說明 & 狀態列 ---
            tips = ttk.LabelFrame(self, text="提示"); tips.pack(fill="both", expand=True, padx=12, pady=10)
            txt = ("1) 匯出證據包 (Evidence Bundle) 包含: page_snapshot.html, resources/, manifest.json, hashes_sha256.txt, report.html\n"
                   "2) 蒐證時務必停用瀏覽器快取 (Disable Cache)，並選擇 `Save all as HAR with content`。\n"
                   "3) 對於動態/SPA網站，`基底快照` 是確保高還原度的關鍵。")
            tk.Label(tips, text=txt, justify='left', anchor='w', wraplength=720).pack(fill="both", padx=10, pady=8)

            self.status_var = tk.StringVar(
                value=f"待命  |  版本 {__version__}  |  作者 {__author__}\n{UNIT_STR}"
            )
            ttk.Label(
                self,
                textvariable=self.status_var,
                foreground="#444",
                anchor="center",
                justify="center"
            ).pack(side="bottom", fill="x", padx=12, pady=(0,10))
            
            # --- 自動啟動 ---
            if args.har:
                self.after(100, self.start_server)

            self.protocol("WM_DELETE_WINDOW", self.on_close)

        def choose_har(self): self.har_var.set(filedialog.askopenfilename(filetypes=[("HAR","*.har"),("All","*.*")]))
        def choose_snap(self): self.snap_var.set(filedialog.askopenfilename(filetypes=[("HTML","*.html;*.htm"),("All","*.*")]))

        def start_server(self):
            if self.srv["httpd"]: messagebox.showinfo("提示", "伺服器已在執行。"); return
            har = self.har_var.get().strip()
            if not har or not os.path.exists(har): messagebox.showerror("錯誤", "請選擇有效的 HAR 檔。"); return
            snap = self.snap_var.get().strip() or None
            
            def on_ready(url):
                self.status_var.set(f"伺服器已啟動: {url}")
                self.btn_start.config(state="disabled")
                self.btn_stop.config(state="normal")
                self.btn_open.config(state="normal")
                webbrowser.open(url)
            
            def on_error(msg):
                self.status_var.set(f"啟動失敗: {msg}")
                messagebox.showerror("啟動失敗", msg)
            
            httpd, th = run_server(har, snap, port=self.port_var.get(), on_ready=on_ready, on_error=on_error)
            if httpd:
                self.srv.update({"httpd": httpd, "th": th})

        def stop_server(self):
            if self.srv["httpd"]:
                try: self.srv["httpd"].shutdown(); self.srv["httpd"].server_close()
                except Exception: pass
                self.srv["httpd"] = None; self.srv["th"] = None
                self.status_var.set(f"伺服器已停止。")
                self.btn_start.config(state="normal")
                self.btn_stop.config(state="disabled")
                self.btn_open.config(state="disabled")

        def do_export(self):
            har = self.har_var.get().strip()
            if not har or not os.path.exists(har): messagebox.showerror("錯誤", "請選擇有效的 HAR 檔。"); return
            snap = self.snap_var.get().strip() or None
            try:
                state = AppState(har, snap)
                out_dir = os.path.abspath("evidence_bundle")
                ts = self.ts_var.get().strip()
                Exporter(state.har, state.composer, out_dir).run(mode=self.mode_var.get(), ts_iso=iso_norm(ts) if ts else None)
                messagebox.showinfo("完成", f"已成功匯出證據包至資料夾：\n{out_dir}")
                os.startfile(out_dir) # Open folder
            except Exception as e:
                messagebox.showerror("匯出失敗", f"發生錯誤: {e}")

        # --- v1 Forensic Tools Methods ---
        def open_forensic_tips(self):
            tips = tk.Toplevel(self); tips.title("現場快速取證教學"); tips.geometry("660x540"); tips.resizable(False, False)
            txt_widget = tk.Text(tips, wrap="word", padx=10, pady=10); txt_widget.pack(fill="both", expand=True)
            guide = (
                "【現場快速蒐證建議】\n"
                "1) 全程螢幕錄影：從操作開始到結束，包含網址列、系統時間。\n\n"
                "2) 儲存靜態畫面 (PDF)：按 Ctrl+P (或列印) → 另存為 PDF。\n\n"
                "3) 取得 HAR (含內容)：\n"
                "   a. 開啟開發者工具 (F12) → Network (網路) 分頁。\n"
                "   b. 勾選 ☑ Disable cache (停用快取)。\n"
                "   c. 操作網頁，重現要取證的畫面。\n"
                "   d. 在請求列表上按右鍵 → Save all as HAR with content。\n\n"
                "4) 取得 DOM 快照 (高度建議)：\n"
                "   a. 在開發者工具中切換到 Console (主控台) 分頁。\n"
                "   b. (若瀏覽器阻擋貼上) 先輸入 `allow pasting` 並按 Enter。\n"
                "   c. 貼上指令 `copy(document.documentElement.outerHTML);` 並按 Enter。\n"
                "   d. 回到本工具，按「從剪貼簿存成 HTML...」儲存。\n\n"
                "5) 將 HAR 和 DOM 快照檔載入本工具，進行回放或匯出證據包。"
            )
            txt_widget.insert("1.0", guide); txt_widget.config(state="disabled")
            ttk.Button(tips, text="關閉", command=tips.destroy).pack(pady=10)

        def copy_to_clipboard(self, s: str):
            try:
                self.clipboard_clear(); self.clipboard_append(s); self.update()
                messagebox.showinfo("已複製", "指令已複製到剪貼簿。\n請到瀏覽器 Console 貼上執行。")
            except Exception as e: messagebox.showerror("複製失敗", f"無法寫入剪貼簿: {e}")

        def save_clipboard_to_html(self):
            try: txt = self.clipboard_get()
            except Exception: messagebox.showerror("讀取失敗", "無法讀取剪貼簿內容。"); return
            if not txt or "<html" not in txt.lower():
                messagebox.showwarning("內容警告", "剪貼簿內容似乎不是完整 HTML，請確認已正確執行指令。")

            p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html;*.htm")], title="儲存 DOM 快照")
            if not p: return
            try:
                with open(p, "w", encoding="utf-8") as f: f.write(txt)
                self.snap_var.set(p)
                messagebox.showinfo("儲存成功", f"已將剪貼簿內容存為檔案，並自動填入「基底快照」欄位:\n{p}")
            except Exception as e: messagebox.showerror("儲存失敗", f"寫入檔案時發生錯誤: {e}")

        def on_close(self):
            self.stop_server()
            self.destroy()

    app = App(args)
    app.mainloop()

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description=f"HAR Replay Pro {__version__} — Evidence-Grade Replayer")
    ap.add_argument("--har", help="Path to HAR file")
    ap.add_argument("--snapshot", help="Path to DOM snapshot HTML (optional)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--headless", action="store_true", help="Run without GUI (web UI only)")
    args = ap.parse_args()

    if args.headless:
        if not args.har or not os.path.exists(args.har):
            print("[!] Headless 模式需要 --har 參數指定 HAR 檔路徑。"); sys.exit(1)
        
        def on_ready(url): print(f"[*] 無頭模式伺服器已啟動: {url}"); print("[*] 按 Ctrl+C 停止。")
        def on_error(msg): print(f"[!] 伺服器錯誤: {msg}"); sys.exit(1)
            
        httpd, th = run_server(args.har, args.snapshot, args.port, on_ready, on_error)
        if th:
            try: th.join()
            except KeyboardInterrupt: print("\n[*] 正在關閉伺服器..."); httpd.shutdown()
        return

    start_gui(args)

if __name__ == "__main__":
    main()
