# -*- coding: utf-8 -*-
"""
HAR Replay (GUI + CLI) — list-first + table UI + compose views
- 預設開啟「回放清單」：專業、易懂的表格（時間 / 路徑 / 預覽）
- 「最終合成」兩種模式：外聯補資源（ext=on）/ 純本機（ext=off）
- 依時間（新→舊）直接預覽，點即開新分頁
- ThreadingHTTPServer + timeouts → 停止更快
- 保守改寫 + 外聯模式切換
- 友善 GUI：版本號、作者、簡易說明、預設啟動自動開清單
- 進階憑證（預設隱藏）
- 視窗 icon（app.ico / app.png）、GUI 橫幅（banner.png）
- PyInstaller -F 打包相容（resource_path）

作者（__author__）：Chiakai
版本（__version__）：20250822.06
"""

import argparse
import base64
import html
import json
import os
import re
import ssl
import sys
import threading
import webbrowser
from datetime import datetime
from urllib.parse import urlsplit, parse_qs

from socketserver import ThreadingMixIn
from http.server import HTTPServer, BaseHTTPRequestHandler

__author__  = "Chiakai"
__version__ = "20250822.06"

# ------------ 資源路徑（支援 PyInstaller 單檔） ------------
def resource_path(relative_path: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)

APP_ICON_CANDIDATES = ["app.ico", "app.png"]  # 視窗 icon 任一存在就用
BANNER_FILE = "banner.png"                     # GUI 橫幅圖（選填）

# ---------- 讀取 HAR & 建索引 ----------
def parse_started_dt(entry):
    dt_str = (entry.get("startedDateTime") or "").strip()
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None

def load_har(har_path):
    with open(har_path, 'rb') as f:
        har = json.load(f)

    entries = har.get('log', {}).get('entries', [])
    maps = {'by_full': {}, 'by_path_qs': {}}
    url_list = []
    origins = set()
    rewrite_map = set()
    html_entries = []   # [(started_dt, path_qs, full_url, status, content_type, body_len, origin)]

    # 以「主要網域」推測主頁（啟發式：以最大量的 HTML 來源網域）
    domain_count = {}

    for e in entries:
        req = e.get('request', {}) or {}
        res = e.get('response', {}) or {}
        url = req.get('url', '') or ''
        method = (req.get('method') or 'GET').upper()
        u = urlsplit(url)
        path_qs = u.path + (('?' + u.query) if u.query else '')
        started_dt = parse_started_dt(e)
        origin = f"{u.scheme}://{u.netloc}" if (u.scheme and u.netloc) else ""

        if origin:
            origins.add(origin)

        # body
        content = res.get('content', {}) or {}
        text = content.get('text')
        encoding = content.get('encoding')
        body = b''
        if text is not None:
            if encoding == 'base64':
                try:
                    body = base64.b64decode(text)
                except Exception:
                    body = text.encode('utf-8', 'ignore')
            else:
                body = text.encode('utf-8', 'ignore')

        # headers
        headers = {}
        for h in (res.get('headers') or []):
            name = (h.get('name') or h.get('Name') or '').strip()
            value = (h.get('value') or h.get('Value') or '')
            if name:
                headers[name.lower()] = value

        status = int(res.get('status') or 200)
        ct = headers.get('content-type', '') or ''

        rec = {
            'status': status,
            'headers': headers,
            'body': body,
            'url': url,
            'method': method,
            'path_qs': path_qs,
            'origin': origin,
        }

        maps['by_full'][(method, url)] = rec
        maps['by_path_qs'][(method, path_qs)] = rec
        url_list.append(url)

        # 收錄 rewrite_map：只記「GET 且 body 不為空」的完整絕對 URL
        if method == 'GET' and url and body:
            rewrite_map.add(url)

        # 蒐集 HTML 候選（用於時間清單與主頁推測）
        if method == 'GET' and status == 200 and 'text/html' in ct.lower():
            html_entries.append((started_dt, path_qs, url, status, ct, len(body or b''), origin))
            # 統計來源網域（作為主網域推測）
            if origin:
                domain_count[origin] = domain_count.get(origin, 0) + 1

    # 依時間排序（新→舊）
    html_entries.sort(key=lambda x: (x[0] or datetime.min), reverse=True)

    # 推測主網域：HTML 出現最多的 origin（如果沒有就 None）
    main_origin = None
    if domain_count:
        main_origin = max(domain_count.items(), key=lambda kv: kv[1])[0]

    # 主頁推測：在主網域中，選擇第一個 HTML 的 path_qs
    main_path_qs = None
    if main_origin:
        for (dtv, pqs, full, st, ct, blen, origin) in html_entries:
            if origin == main_origin:
                main_path_qs = pqs
                break
    # 若仍無，退而求其次用第一筆 HTML
    if not main_path_qs and html_entries:
        main_path_qs = html_entries[0][1]

    return {
        'maps': maps,
        'url_list': url_list,
        'origins': origins,
        'main_path_qs': main_path_qs,
        'main_origin': main_origin,
        'rewrite_map': rewrite_map,
        'html_entries': html_entries,  # 給清單/compose用
    }

# ---------- HTML 改寫 ----------
def _replace_abs_urls_with_local(html_text, server_base, rewrite_map, allow_external):
    """
    allow_external=True ：外聯補資源 → 只把 HAR 有的絕對 URL 改為本機，其餘保持原樣（交由瀏覽器上網抓）
    allow_external=False：純本機 → HAR 見過的所有 origin 一律改成本機，即便沒 body（避免外聯）
    """
    out = html_text
    if allow_external:
        # 只改我們確定有 body 的完整 URL
        for full_url in list(rewrite_map):
            u = urlsplit(full_url)
            path_qs = u.path + (('?' + u.query) if u.query else '')
            out = out.replace(full_url, f"{server_base}{path_qs}")

        # 針對上述 URL 的主機，處理協定相對（//host/...）
        seen_hosts = {urlsplit(u).netloc for u in rewrite_map}
        for host in list(seen_hosts):
            pattern = re.compile(r'(?P<prefix>["\'(])//' + re.escape(host) + r'(?P<path>/[^"\'\s)]+)')
            def _sub(m):
                return m.group('prefix') + f"{server_base}{m.group('path')}"
            out = pattern.sub(_sub, out)
        return out

    # 純本機：將 HAR 見過的所有 origin 改成 server_base
    origins = set(urlsplit(u).scheme + "://" + urlsplit(u).netloc for u in rewrite_map)
    for origin in origins:
        out = out.replace(origin, server_base)
        # 協定相對
        host = urlsplit(origin).netloc
        out = out.replace(f"//{host}", f"//localhost:{urlsplit(server_base).port or ''}".rstrip(':'))
    return out

def rewrite_html(body_bytes, server_scheme, server_port, ctx, allow_external=True):
    # 試著解碼
    html_text = None
    for enc in ('utf-8', 'latin-1'):
        try:
            html_text = body_bytes.decode(enc)
            break
        except Exception:
            continue
    if html_text is None:
        return body_bytes

    server_base = f"{server_scheme}://localhost:{server_port}"
    rewrite_map = ctx.get('rewrite_map', set())
    html_text = _replace_abs_urls_with_local(html_text, server_base, rewrite_map, allow_external)

    return html_text.encode('utf-8')

# ---------- Threading HTTP Server（停止更快） ----------
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

# ---------- HTTP Handler ----------
class HarHandler(BaseHTTPRequestHandler):
    ctx = None
    server_port = None

    def do_GET(self): self._serve()
    def do_POST(self): self._serve()
    def log_message(self, fmt, *args): pass

    def _send_bytes(self, body: bytes, ctype="text/html; charset=utf-8", status=200):
        self.send_response(status)
        if ctype:
            self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _compose_html(self, html_rec, scheme, allow_external):
        """把單一 HTML 回應做改寫並回傳 bytes"""
        if not html_rec:
            page = "<!doctype html><meta charset='utf-8'><title>No HTML</title><h2>沒有可用的 HTML</h2>"
            return page.encode("utf-8")
        body = html_rec['body'] or b""
        return rewrite_html(body, scheme, self.server_port, self.ctx, allow_external=allow_external)

    def _serve(self):
        ctx = self.ctx
        maps = ctx['maps']
        url_list = ctx['url_list']
        html_entries = ctx.get('html_entries', [])
        main_path_qs = ctx.get('main_path_qs')
        main_origin = ctx.get('main_origin')

        method = self.command.upper()
        path_qs = self.path

        # === 清單頁（預設） ===
        if path_qs == "/" or path_qs.startswith("/__list"):
            main_pqs = main_path_qs or "(未定)"
            page = self._render_list_page(main_pqs, html_entries)
            self._send_bytes(page.encode("utf-8"))
            return

        # === 偵錯頁 ===
        if path_qs.startswith("/__debug"):
            stats = {
                "version": __version__,
                "main_origin": main_origin,
                "main_path_qs": main_path_qs,
                "html_entries_count": len(html_entries),
                "port": self.server_port,
            }
            pretty = json.dumps(stats, ensure_ascii=False, indent=2)
            page = f"<!doctype html><meta charset='utf-8'><title>Debug</title><pre>{html.escape(pretty)}</pre><p><a href='/'>返回清單</a></p>"
            self._send_bytes(page.encode("utf-8"))
            return

        # === 合成頁：最終或指定時間 ===
        if path_qs.startswith("/__compose"):
            # 參數：view=[final|time] ; ts=ISO ; ext=on/off
            qs = ""
            if "?" in path_qs:
                qs = path_qs.split("?", 1)[1]
            params = parse_qs(qs or "")
            view = (params.get("view") or ["final"])[0]
            ext  = (params.get("ext") or ["on"])[0]
            allow_external = (ext.lower() == "on")

            is_tls = isinstance(self.server.socket, ssl.SSLSocket)
            scheme = 'https' if is_tls else 'http'

            target_rec = None
            if view == "final":
                # 以主頁 path_qs 尋找對應 HTML（若無，降級第一筆）
                if main_path_qs:
                    target_rec = maps['by_path_qs'].get(('GET', main_path_qs))
                if not target_rec and html_entries:
                    # 用時間最新的
                    latest_pqs = html_entries[0][1]
                    target_rec = maps['by_path_qs'].get(('GET', latest_pqs))
            else:
                # 指定時間點：找離該 ts 最近、且時間 <= ts 的 HTML
                ts_str = (params.get("ts") or [""])[0]
                cutoff = None
                try:
                    cutoff = datetime.fromisoformat(ts_str)
                except Exception:
                    cutoff = None
                chosen = None
                if cutoff and html_entries:
                    for (dtv, pqs, full, st, ct, blen, origin) in html_entries:
                        if dtv and dtv <= cutoff:
                            chosen = (dtv, pqs)
                            break
                if chosen:
                    target_rec = maps['by_path_qs'].get(('GET', chosen[1]))
                elif html_entries:
                    target_rec = maps['by_path_qs'].get(('GET', html_entries[-1][1]))

            body = self._compose_html(target_rec, scheme, allow_external)
            # 包裝成最簡容器頁（避免因 <base> 等影響）
            html_shell = f"""<!doctype html><html><head><meta charset="utf-8">
<title>HAR Compose</title></head><body>
<!-- composed -->
{body.decode('utf-8', errors='ignore')}
</body></html>"""
            self._send_bytes(html_shell.encode("utf-8"))
            return

        # === 其他資源（靜態回放） ===
        # 先用 path+query 找
        rec = maps['by_path_qs'].get((method, path_qs))
        if not rec:
            # 再嘗試用完整 URL（以目前 Host + scheme）
            is_tls = isinstance(self.server.socket, ssl.SSLSocket)
            scheme = 'https' if is_tls else 'http'
            host = self.headers.get('Host', '').strip()
            if host:
                full_url = f"{scheme}://{host}{path_qs}"
                rec = maps['by_full'].get((method, full_url))

        if not rec:
            msg = f"Not found in HAR: {method} {path_qs}\n"
            self._send_bytes(msg.encode("utf-8"), ctype="text/plain; charset=utf-8", status=404)
            return

        status = rec['status']
        headers = rec['headers']
        body = rec['body'] or b""
        ct = headers.get('content-type', '')

        # 靜態資源原樣回放（HTML 不改寫；合成改寫只在 /__compose）
        self.send_response(status)
        if ct: self.send_header('content-type', ct)
        self.send_header('content-length', str(len(body)))
        self.send_header('cache-control', 'no-cache')
        self.end_headers()
        if body:
            self.wfile.write(body)

    # ---- 清單頁渲染（表格） ----
    def _render_list_page(self, main_pqs, html_entries):
        main_pqs_disp = html.escape(main_pqs or "(未定)")

        def fmt_dt(dt):
            try: return dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception: return "(no time)"

        rows = []
        for (dtv, pqs, full, st, ct, blen, origin) in html_entries:
            ts = dtv.isoformat() if dtv else ""
            dt_disp  = html.escape(fmt_dt(dtv))
            pqs_disp = html.escape(pqs or "")
            rows.append(
                f"""<tr>
                      <td class="col-time"><code>{dt_disp}</code></td>
                      <td class="col-url"><code>{pqs_disp}</code></td>
                      <td class="col-actions">
                        <a class="btn small primary" target="_blank" rel="noopener" href="/__compose?view=time&ts={ts}&ext=on">預覽（外聯補資源）</a>
                        <a class="btn small"          target="_blank" rel="noopener" href="/__compose?view=time&ts={ts}&ext=off">預覽（純本機）</a>
                      </td>
                    </tr>"""
            )
        rows_html = ("\n".join(rows)) if rows else \
                    "<tr><td colspan='3' class='empty'>（此 HAR 找不到 HTML）</td></tr>"

        page = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>HAR Replay / List</title>
<style>
 body {{ font-family: -apple-system, BlinkMacSystemFont, "Noto Sans CJK TC", "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color:#222; }}
 .wrap {{ max-width: 1000px; margin: 28px auto; padding: 0 16px; }}
 h1 {{ margin: 0 0 10px; }}
 .subtle {{ color:#666; margin: 0 0 18px; }}
 .callout {{ background:#f6f8fa; border:1px solid #eaecef; padding:14px 16px; border-radius:8px; margin:18px 0; }}
 .btn {{ display:inline-block; padding:8px 14px; border-radius:6px; text-decoration:none; border:1px solid #d0d7de; background:#fff; color:#0969da; }}
 .btn.primary {{ background:#0969da; color:#fff; border-color:#0969da; }}
 .btn.small {{ padding:6px 10px; font-size: 12px; }}
 .footer {{ color:#555; margin-top: 18px; text-align:right; }}

 table {{ width:100%; border-collapse:collapse; table-layout: fixed; }}
 thead th {{ text-align:left; font-weight:600; color:#444; border-bottom:1px solid #eaecef; padding:8px 10px; }}
 tbody td {{ vertical-align:top; border-bottom:1px solid #f0f2f4; padding:10px; }}
 code {{ background:#eef2f6; padding:2px 6px; border-radius:4px; }}

 .col-time {{ width: 160px; white-space:nowrap; }}
 .col-url  {{ width: 600px; overflow-wrap:anywhere; word-break:break-all; }}
 .col-actions {{ width: 200px; }}
 .col-actions a {{ display:block; margin-bottom:6px; text-align:center; }}
 .col-actions a:last-child {{ margin-bottom:0; }}
 .empty {{ color:#666; text-align:center; padding:18px 0; }}
</style>
</head>
<body><div class="wrap">
  <h1>HAR 回放清單</h1>
  <p class="subtle">當前程式版本：{__version__}</p>

  <div class="callout">
    <p style="margin:0 0 6px;">
      <strong>建議：</strong>先按「最終合成」，我們會以主要網站的主頁為基礎，把同網域中最後可用的資源補上。<br>
      目前偵測的主頁：<code>{main_pqs_disp}</code>
    </p>
    <p style="margin:8px 0 0;">
      <a class="btn primary" target="_blank" rel="noopener" href="/__compose?view=final&ext=on">最終合成（外聯補資源）</a>
      <a class="btn" target="_blank" rel="noopener" href="/__compose?view=final&ext=off">最終合成（純本機）</a>
      <a class="btn" target="_blank" rel="noopener" href="/__debug">偵錯資訊</a>
    </p>
  </div>

  <h3>依時間預覽（新 → 舊）</h3>
  <table>
    <thead>
      <tr><th class="col-time">時間</th><th class="col-url">路徑（path+query）</th><th class="col-actions">預覽</th></tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>

  <h3>說明</h3>
  <div class="callout">
    <ul>
      <li><strong>外聯補資源</strong>：我們有存到的檔改寫成本機；沒存到的保留原網址 → 瀏覽器會上網補齊，外觀更接近當時。</li>
      <li><strong>純本機</strong>：HAR 見過的網域一律指回本機，不會對外連線（缺的資源會顯示不出）。</li>
      <li>合成屬「靜態回填」：不執行 JavaScript；互動/廣告/外掛不一定能完全重播。</li>
    </ul>
  </div>

  <p class="footer">臺中市政府警察局刑事警察大隊科技犯罪偵查隊</p>
</div></body></html>"""
        return page

# ---------- 啟動伺服器（GUI/CLI 共用） ----------
def run_server(har_path, port=3000, cert=None, key=None, on_ready=None, on_error=None):
    try:
        ctx = load_har(har_path)
    except Exception as e:
        if on_error: on_error(f"讀取 HAR 失敗：{e}")
        else: print(f"[HAR Replay] 讀取 HAR 失敗：{e}")
        return None

    httpd = ThreadingHTTPServer(("0.0.0.0", int(port)), HarHandler)
    httpd.timeout = 0.5
    try:
        httpd.socket.settimeout(1.0)
    except Exception:
        pass

    HarHandler.ctx = ctx
    HarHandler.server_port = int(port)

    scheme = "http"
    if cert and key:
        try:
            sc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sc.load_cert_chain(cert, key)
            httpd.socket = sc.wrap_socket(httpd.socket, server_side=True)
            scheme = "https"
        except Exception as e:
            if on_error: on_error(f"載入憑證失敗：{e}")
            else: print(f"[HAR Replay] 載入憑證失敗：{e}")
            return None

    def _serve():
        if on_ready: on_ready(scheme)
        try:
            httpd.serve_forever()
        except Exception as e:
            if on_error: on_error(f"伺服器例外：{e}")

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return httpd, t, scheme

# ---------- GUI ----------
def start_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinter import PhotoImage

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(f"HAR Replay  v{__version__}  —  by {__author__}")
            self.geometry("700x520")
            self.resizable(False, False)

            # 視窗 icon（優先 .ico，沒有就用 .png）
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

            self.httpd = None
            self.srv_thread = None
            self.scheme = "http"

            # 上方：簡單說明 + 橫幅圖
            top = ttk.Frame(self); top.pack(fill="x", padx=12, pady=(10,4))

            banner_path = resource_path(BANNER_FILE)
            self._banner_img = None
            if os.path.isfile(banner_path):
                try:
                    self._banner_img = PhotoImage(file=banner_path)
                    ttk.Label(top, image=self._banner_img).pack(anchor="c", pady=(6,10))
                except Exception:
                    pass

            intro = (
                "這是一個簡單的 HAR 回放工具：\n"
                "1) 選擇 .har 檔 → 2) 按「啟動」→ 瀏覽器會自動打開「回放清單」，\n"
                "   再點「最終合成」或任一時間的預覽，即可看到重播畫面。\n"
                "※ HAR 僅記請求/回應，不含 DOM/JS 執行；合成為靜態回填（最佳努力）。"
            )
            ttk.Label(top, text=intro, foreground="#333").pack(anchor="w")

            # 檔案/埠號
            frm1 = ttk.Frame(self); frm1.pack(fill="x", padx=12, pady=(10,6))
            ttk.Label(frm1, text="HAR 檔案：").pack(side="left")
            self.har_var = tk.StringVar()
            ttk.Entry(frm1, textvariable=self.har_var).pack(side="left", fill="x", expand=True, padx=6)
            ttk.Button(frm1, text="選擇…", command=self.choose_har).pack(side="left")

            frm2 = ttk.Frame(self); frm2.pack(fill="x", padx=12, pady=6)
            ttk.Label(frm2, text="Port：").pack(side="left")
            self.port_var = tk.StringVar(value="3000")
            ttk.Entry(frm2, width=8, textvariable=self.port_var).pack(side="left", padx=(6,10))

            # 進階（憑證）
            adv_hdr = ttk.Frame(self); adv_hdr.pack(fill="x", padx=12, pady=(6,0))
            self.show_adv = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                adv_hdr, text="顯示進階設定（HTTPS 憑證）",
                variable=self.show_adv, command=self.toggle_adv
            ).pack(anchor="w")

            meta = ttk.Frame(self); meta.pack(fill="x", padx=12, pady=(2,0))
            ttk.Label(
                meta,
                text=f"臺中市政府警察局刑事警察大隊科技犯罪偵查隊  ｜   作者：{__author__}  ｜   版本：{__version__}",
                foreground="#555"
            ).pack(side="right")

            self.adv = ttk.Frame(self); self.adv.pack(fill="x", padx=12, pady=(0,6))
            ttk.Label(self.adv, text="Cert：").grid(row=0, column=0, sticky="w")
            self.cert_var = tk.StringVar()
            self.cert_entry = ttk.Entry(self.adv, textvariable=self.cert_var, width=48)
            self.cert_entry.grid(row=0, column=1, sticky="ew", padx=6)
            ttk.Button(self.adv, text="選擇…", command=self.choose_cert).grid(row=0, column=2, sticky="w")

            ttk.Label(self.adv, text="Key：").grid(row=1, column=0, sticky="w", pady=(4,0))
            self.key_var = tk.StringVar()
            self.key_entry = ttk.Entry(self.adv, textvariable=self.key_var, width=48)
            self.key_entry.grid(row=1, column=1, sticky="ew", padx=6, pady=(4,0))
            ttk.Button(self.adv, text="選擇…", command=self.choose_key).grid(row=1, column=2, sticky="w", pady=(4,0))
            self.adv.grid_columnconfigure(1, weight=1)
            self.adv.pack_forget()

            # 控制列
            ctrl = ttk.Frame(self); ctrl.pack(fill="x", padx=12, pady=10)
            ttk.Button(ctrl, text="關於我", command=self.open_portfolio).pack(side="left", padx=(6,0))
            ttk.Button(ctrl, text="回饋表單", command=self.open_feedback).pack(side="left")

            self.btn_start = ttk.Button(ctrl, text="啟動", command=self.on_start)
            self.btn_start.pack(side="right")
            self.btn_stop  = ttk.Button(ctrl, text="停止", command=self.on_stop, state="disabled")
            self.btn_stop.pack(side="right", padx=6)
            self.btn_open  = ttk.Button(ctrl, text="開啟瀏覽器", command=self.open_browser, state="disabled")
            self.btn_open.pack(side="right", padx=6)

            # 狀態列
            self.status_var = tk.StringVar(
                value=f"待命  |  版本 {__version__}  |  作者 {__author__}\n臺中市政府警察局刑事警察大隊科技犯罪偵查隊"
            )
            ttk.Label(self, textvariable=self.status_var, foreground="#444").pack(
                side="right", fill="x", padx=12, pady=(0,10)
            )

            self.protocol("WM_DELETE_WINDOW", self.on_close)

        def choose_har(self):
            from tkinter import filedialog
            p = filedialog.askopenfilename(filetypes=[("HAR files", "*.har"), ("All files", "*.*")])
            if p: self.har_var.set(p)

        def choose_cert(self):
            from tkinter import filedialog
            p = filedialog.askopenfilename(filetypes=[("PEM certificate", "*.pem"), ("All files", "*.*")])
            if p: self.cert_var.set(p)

        def choose_key(self):
            from tkinter import filedialog
            p = filedialog.askopenfilename(filetypes=[("PEM private key", "*.pem;*.key"), ("All files", "*.*")])
            if p: self.key_var.set(p)

        def toggle_adv(self):
            if self.show_adv.get():
                self.adv.pack(fill="x", padx=12, pady=(0,6))
            else:
                self.adv.pack_forget()

        def on_start(self):
            if self.httpd: return
            har = self.har_var.get().strip()
            if not har or not os.path.isfile(har):
                from tkinter import messagebox
                messagebox.showerror("錯誤", "請選擇有效的 HAR 檔案"); return
            try:
                port = int(self.port_var.get().strip() or "3000")
            except ValueError:
                from tkinter import messagebox
                messagebox.showerror("錯誤", "Port 必須是數字"); return

            cert = self.cert_var.get().strip() if self.show_adv.get() and self.cert_var.get().strip() else None
            key  = self.key_var.get().strip()  if self.show_adv.get() and self.key_var.get().strip()  else None
            if (cert and not key) or (key and not cert):
                from tkinter import messagebox
                messagebox.showerror("錯誤", "若使用 HTTPS，請同時提供憑證與金鑰（PEM）"); return

            def on_ready(scheme):
                self.scheme = scheme
                self.status_var.set(f"伺服器已啟動：{scheme}://localhost:{port}   （清單：/；偵錯：/__debug）")
                self.btn_start.configure(state="disabled")
                self.btn_stop.configure(state="normal")
                self.btn_open.configure(state="normal")
                # 預設自動開清單頁
                webbrowser.open(f"{scheme}://localhost:{port}/")

            def on_error(msg):
                from tkinter import messagebox
                self.status_var.set(f"錯誤：{msg}")
                messagebox.showerror("啟動失敗", msg)

            out = run_server(har, port=port, cert=cert, key=key, on_ready=on_ready, on_error=on_error)
            if out is None: return
            self.httpd, self.srv_thread, self.scheme = out[0], out[1], out[2]

        def on_stop(self):
            if not self.httpd: return
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None
            self.srv_thread = None
            self.btn_start.configure(state="normal" if self.har_var.get().strip() else "disabled")
            self.btn_stop.configure(state="disabled")
            self.btn_open.configure(state="disabled")
            self.status_var.set(f"已停止  |  版本 {__version__}  |  作者 {__author__}\n臺中市政府警察局刑事警察大隊科技犯罪偵查隊")

        def open_browser(self):
            if not self.httpd: return
            try:
                port = int(self.port_var.get().strip() or "3000")
            except ValueError:
                port = 3000
            webbrowser.open(f"{self.scheme}://localhost:{port}/")

        def open_portfolio(self):
            webbrowser.open("https://chiakai-chang.github.io/CKTools/")

        def open_feedback(self):
            webbrowser.open("https://forms.gle/euDVcKwk7QsiHgsz8")

        def on_close(self):
            try: self.on_stop()
            finally: self.destroy()

    App().mainloop()

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description=f"Minimal HAR replay server (GUI + CLI)  v{__version__}  by {__author__}")
    ap.add_argument("--har", help="Path to HAR file")
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--cert", help="PEM cert for HTTPS (advanced)")
    ap.add_argument("--key", help="PEM key for HTTPS (advanced)")
    ap.add_argument("--gui", action="store_true", help="Force GUI mode")
    args = ap.parse_args()

    if args.gui or not args.har:
        try: start_gui()
        except KeyboardInterrupt: pass
        return

    out = run_server(args.har, port=args.port, cert=args.cert, key=args.key)
    if out is None: sys.exit(1)
    httpd, t, scheme = out
    print(f"[HAR Replay v{__version__}] Serving on {scheme}://localhost:{args.port}  (/ , /__debug)")
    try:
        t.join()
    except KeyboardInterrupt:
        httpd.shutdown(); httpd.server_close()

if __name__ == "__main__":
    main()
