# -*- coding: utf-8 -*-
"""
HAR Replay (GUI + CLI) — safer replay + quick stop + homepage selector
- ThreadingHTTPServer (daemon threads) + timeouts -> 停止更快
- 自動把「最新的」HTML 當首頁，並提供 GUI 下拉切換不同時間版本
- 保守改寫：只改寫 HAR 內「確實存在本體」的絕對網址，避免外機器白畫面
- 友善 GUI：版本號、作者、簡易說明、預設啟動自動開瀏覽器
- 隱藏的進階憑證設定（預設不顯示，勾選才展開）
- 兩個圖片位子：視窗 icon（app.ico / app.png）、GUI 橫幅（banner.png）
- /__list、/__debug、/__set_home?path=... 皆保留
- PyInstaller -F 打包相容（resource_path）

Created on Mon Feb  3 09:25:57 2025
最後更新：2025-08-21
作者（__author__）：Chiakai
版本（__version__）：20250822.02
"""

import argparse
import base64
import json
import os
import re
import ssl
import sys
import threading
import webbrowser
import socket
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit, parse_qs

from socketserver import ThreadingMixIn
from http.server import HTTPServer

__author__  = "Chiakai"
__version__ = "20250821.03"

# ------------ 資源路徑（支援 PyInstaller 單檔） ------------

def resource_path(relative_path: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)

APP_ICON_CANDIDATES = ["app.ico", "app.png"]  # 視窗 icon 任一存在就用
BANNER_FILE = "banner.png"                     # GUI 橫幅圖（選填）


# ---------- 讀取 HAR & 建索引 ----------

def parse_started_dt(entry):
    # HAR 常用欄位 log.entries[i].startedDateTime（ISO 8601）
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
    html_entries = []   # [(started_dt, path_qs, full_url, status, content_type)]

    main_path_qs = None

    for e in entries:
        req = e.get('request', {}) or {}
        res = e.get('response', {}) or {}
        url = req.get('url', '') or ''
        method = (req.get('method') or 'GET').upper()
        u = urlsplit(url)
        path_qs = u.path + (('?' + u.query) if u.query else '')
        started_dt = parse_started_dt(e)

        if u.scheme and u.netloc:
            origins.add(f"{u.scheme}://{u.netloc}")

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
        rec = {'status': status, 'headers': headers, 'body': body,
               'url': url, 'method': method, 'path_qs': path_qs}

        maps['by_full'][(method, url)] = rec
        maps['by_path_qs'][(method, path_qs)] = rec
        url_list.append(url)

        # 收錄 rewrite_map：只記「GET 且 body 不為空」的完整絕對 URL
        if method == 'GET' and url and body:
            rewrite_map.add(url)

        ct = headers.get('content-type', '')
        if method == 'GET' and status == 200 and 'text/html' in (ct or '').lower():
            html_entries.append((started_dt, path_qs, url, status, ct))

    # 依時間排序（新→舊）
    html_entries.sort(key=lambda x: (x[0] or datetime.min), reverse=True)
    if html_entries:
        # 預設選最新一筆
        main_path_qs = html_entries[0][1]

    return {
        'maps': maps,
        'url_list': url_list,
        'origins': origins,
        'main_path_qs': main_path_qs,
        'rewrite_map': rewrite_map,
        'html_entries': html_entries,  # 給 GUI 與 __list 用
    }

# ---------- 保守 HTML 重寫（只改寫確定可回放的 URL） ----------

def rewrite_html(body_bytes, server_scheme, server_port, origins, rewrite_map):
    # 嘗試解碼
    html = None
    for enc in ('utf-8', 'latin-1'):
        try:
            html = body_bytes.decode(enc)
            break
        except Exception:
            continue
    if html is None:
        return body_bytes

    server_base = f"{server_scheme}://localhost:{server_port}"

    # 1) 逐條把「完整絕對 URL」改成本機 path（只改我們真的有的）
    for full_url in list(rewrite_map):
        u = urlsplit(full_url)
        path_qs = u.path + (('?' + u.query) if u.query else '')
        replacement = f"{server_base}{path_qs}"
        html = html.replace(full_url, replacement)

    # 2) 協定相對（//host/...）→ 僅針對出現在 rewrite_map 的 host
    seen_hosts = {urlsplit(u).netloc for u in rewrite_map}
    for host in list(seen_hosts):
        pattern = re.compile(r'(?P<prefix>["\'(])//' + re.escape(host) + r'(?P<path>/[^"\'\s)]+)')
        def _sub(m):
            return m.group('prefix') + f"{server_base}{m.group('path')}"
        html = pattern.sub(_sub, html)

    return html.encode('utf-8')


# ---------- Threading HTTP Server（停止更快） ----------

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True  # 關閉時不等所有客戶端線程收尾
    allow_reuse_address = True


# ---------- HTTP Handler ----------

class HarHandler(BaseHTTPRequestHandler):
    ctx = None  # {'maps', 'url_list', 'origins', 'main_path_qs', 'rewrite_map', 'html_entries'}
    server_port = None

    def do_GET(self): self._serve()
    def do_POST(self): self._serve()
    def log_message(self, fmt, *args): pass

    def _serve(self):
        ctx = self.ctx
        maps = ctx['maps']
        url_list = ctx['url_list']
        origins = ctx['origins']
        rewrite_map = ctx.get('rewrite_map', set())
        main_path_qs = ctx['main_path_qs']
        html_entries = ctx.get('html_entries', [])

        method = self.command.upper()
        path_qs = self.path

        # 工具：__list
        if path_qs.startswith("/__list"):
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.end_headers()
            link_main = '<p><a href="/">開啟主頁（/）</a></p>' if main_path_qs else "<p>未找到 HTML 主頁。</p>"
            # 列出 HTML 候選（含時間）
            def fmt_dt(dt):
                if not dt: return "(no time)"
                # 以本地時間粗略顯示；如需時區精確可再加 tzinfo 轉換
                try:
                    return dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    return str(dt)
            cand_html = ""
            if html_entries:
                items = []
                for (dtv, pqs, full, st, ct) in html_entries:
                    label = f"{fmt_dt(dtv)}  {pqs}"
                    items.append(f'<li><code>{label}</code> — <a href="/__set_home?path={pqs}">設為首頁</a></li>')
                cand_html = "<h3>HTML 候選（新→舊）：</h3><ul>" + "\n".join(items) + "</ul>"

            html = (
                f"<h1>HAR URLs</h1><p>版本 {__version__} ｜ 作者 {__author__}</p>"
                + link_main + cand_html +
                "<h3>所有請求 URL（原始絕對網址）：</h3>"
                "<ul>" + "".join(f"<li>{u}</li>" for u in url_list) + "</ul>"
                "<p><a href='/__debug'>檢視偵錯資訊</a></p>"
            )
            self.wfile.write(html.encode("utf-8"))
            return

        # 工具：__debug
        if path_qs.startswith("/__debug"):
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.end_headers()
            stats = {
                "main_path_qs": main_path_qs,
                "rewrite_map_count": len(rewrite_map),
                "html_entries_count": len(html_entries),
                "origins": list(origins),
                "port": self.server_port,
                "version": __version__,
            }
            pretty = json.dumps(stats, ensure_ascii=False, indent=2)
            html = f"<h1>Debug</h1><pre>{pretty}</pre><p><a href='/__list'>返回 __list</a></p>"
            self.wfile.write(html.encode("utf-8"))
            return

        # 工具：__set_home?path=...
        if path_qs.startswith("/__set_home"):
            qs = ""
            if "?" in path_qs:
                qs = path_qs.split("?", 1)[1]
            params = parse_qs(qs or "")
            new_home = (params.get("path") or [""])[0]
            if new_home and (('GET', new_home) in maps['by_path_qs']):
                ctx['main_path_qs'] = new_home
                msg = f"已設定首頁為：{new_home}"
            else:
                msg = f"無法設定首頁，找不到：{new_home}"
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<h1>{msg}</h1><p><a href='/'>回首頁</a>｜<a href='/__list'>回清單</a></p>".encode("utf-8"))
            return

        # 把 "/" 對應到 HAR 裡「目前選擇」的主頁
        if path_qs == "/" and ctx['main_path_qs']:
            rec = maps['by_path_qs'].get((method, ctx['main_path_qs']))
        else:
            rec = maps['by_path_qs'].get((method, path_qs))

        # 再嘗試用完整 URL 找（以目前 Host + scheme）
        if not rec:
            is_tls = isinstance(self.server.socket, ssl.SSLSocket)
            scheme = 'https' if is_tls else 'http'
            host = self.headers.get('Host', '').strip()
            if host:
                full_url = f"{scheme}://{host}{path_qs}"
                rec = maps['by_full'].get((method, full_url))

        if not rec:
            self.send_response(404)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"Not found in HAR: {method} {path_qs}\n".encode("utf-8"))
            return

        # 準備輸出
        status = rec['status']
        headers = rec['headers']
        body = rec['body']

        # 如是 HTML，做保守改寫
        ct = headers.get('content-type', '')
        is_tls = isinstance(self.server.socket, ssl.SSLSocket)
        scheme = 'https' if is_tls else 'http'
        if 'text/html' in (ct or '').lower():
            body = rewrite_html(body, scheme, self.server_port, origins, rewrite_map)

        self.send_response(status)
        if ct: self.send_header('content-type', ct)
        self.send_header('content-length', str(len(body)))
        self.send_header('cache-control', 'no-cache')
        self.end_headers()
        if body:
            self.wfile.write(body)


# ---------- 啟動伺服器（GUI/CLI 共用） ----------

def run_server(har_path, port=3000, cert=None, key=None, on_ready=None, on_error=None):
    try:
        ctx = load_har(har_path)
    except Exception as e:
        if on_error: on_error(f"讀取 HAR 失敗：{e}")
        else: print(f"[HAR Replay] 讀取 HAR 失敗：{e}")
        return None

    # Threading server + timeouts -> 停止更快
    httpd = ThreadingHTTPServer(("0.0.0.0", int(port)), HarHandler)
    httpd.timeout = 0.5  # serve_forever 的 poll 間隔
    # 設定底層 socket timeout（避免阻塞太久）
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

            # 設定視窗 icon（優先 .ico，沒有就用 .png）
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
            self._har_ctx = None  # 暫存載入的索引給 GUI 首頁下拉用

            # ===== 上方：簡單說明 + 橫幅圖 =====
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
                "1) 選擇 .har 檔 → 2) 按「載入（不啟動）」可以先選首頁 → 3) 按「啟動」→ 瀏覽器會自動打開主頁（/）\n"
                "※ HAR 是請求/回應紀錄，無法保證 100% 重播；建議搭配螢幕錄影最穩妥。"
            )
            ttk.Label(top, text=intro, foreground="#333").pack(anchor="w")

            # ===== HAR + Port =====
            frm1 = ttk.Frame(self); frm1.pack(fill="x", padx=12, pady=(10,6))
            ttk.Label(frm1, text="HAR 檔案：").pack(side="left")
            self.har_var = tk.StringVar()
            ttk.Entry(frm1, textvariable=self.har_var).pack(side="left", fill="x", expand=True, padx=6)
            ttk.Button(frm1, text="選擇…", command=self.choose_har).pack(side="left")

            frm2 = ttk.Frame(self); frm2.pack(fill="x", padx=12, pady=6)
            ttk.Label(frm2, text="Port：").pack(side="left")
            self.port_var = tk.StringVar(value="3000")
            ttk.Entry(frm2, width=8, textvariable=self.port_var).pack(side="left", padx=(6,10))

            # ===== 首頁選擇（依時間排序） =====
            home_row = ttk.Frame(self); home_row.pack(fill="x", padx=12, pady=(0,6))
            ttk.Label(home_row, text="首頁 HTML：").pack(side="left")
            self.home_choices = []     # [(label, path_qs)]
            self.home_var = tk.StringVar()  # path_qs
            self.home_combo = ttk.Combobox(home_row, textvariable=self.home_var, state="readonly", width=60, values=[])
            self.home_combo.pack(side="left", fill="x", expand=True, padx=6)
            ttk.Button(home_row, text="載入（不啟動）", command=self.preload_har).pack(side="left")

            # ===== 進階（憑證）— 預設隱藏 =====
            adv_hdr = ttk.Frame(self); adv_hdr.pack(fill="x", padx=12, pady=(6,0))
            self.show_adv = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                adv_hdr,
                text="顯示進階設定（HTTPS 憑證）",
                variable=self.show_adv,
                command=self.toggle_adv
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
            self.adv.pack_forget()  # 預設隱藏

            # ===== 控制列 =====
            ctrl = ttk.Frame(self); ctrl.pack(fill="x", padx=12, pady=10)

            ttk.Button(ctrl, text="關於我", command=self.open_portfolio).pack(side="left", padx=(6,0))
            ttk.Button(ctrl, text="回饋表單", command=self.open_feedback).pack(side="left")

            self.btn_start = ttk.Button(ctrl, text="啟動", command=self.on_start, state="disabled")
            self.btn_start.pack(side="right")
            self.btn_stop  = ttk.Button(ctrl, text="停止", command=self.on_stop, state="disabled")
            self.btn_stop.pack(side="right", padx=6)
            self.btn_open  = ttk.Button(ctrl, text="開啟瀏覽器", command=self.open_browser, state="disabled")
            self.btn_open.pack(side="right", padx=6)

            # ===== 狀態列 =====
            self.status_var = tk.StringVar(value=f"待命  |  版本 {__version__}  |  作者 {__author__}\n臺中市政府警察局刑事警察大隊科技犯罪偵查隊")
            ttk.Label(self, textvariable=self.status_var, foreground="#444").pack(side="right", fill="x", padx=12, pady=(0,10))

            self.protocol("WM_DELETE_WINDOW", self.on_close)

        # --- GUI helpers ---
        def choose_har(self):
            from tkinter import filedialog
            p = filedialog.askopenfilename(filetypes=[("HAR files", "*.har"), ("All files", "*.*")])
            if p:
                self.har_var.set(p)
                # 每次挑檔後重置首頁下拉
                self.home_choices = []
                self.home_combo["values"] = []
                self.home_var.set("")
                self._har_ctx = None
                self.btn_start.configure(state="disabled")

        def preload_har(self):
            # 載入 HAR 但不啟動 server，讓使用者先選首頁
            har = self.har_var.get().strip()
            if not har or not os.path.isfile(har):
                from tkinter import messagebox
                messagebox.showerror("錯誤", "請先選擇有效的 HAR 檔案"); return
            try:
                ctx = load_har(har)
            except Exception as e:
                from tkinter import messagebox
                messagebox.showerror("錯誤", f"讀取 HAR 失敗：{e}"); return

            self._har_ctx = ctx
            # 準備首頁選項（依時間新→舊）
            html_entries = ctx.get("html_entries") or []
            def fmt_dt(dt):
                if not dt: return "(no time)"
                try: return dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception: return str(dt)
            choices = []
            for (dtv, pqs, full, st, ct) in html_entries:
                label = f"{fmt_dt(dtv)}  {pqs}"
                choices.append((label, pqs))
            self.home_choices = choices
            self.home_combo["values"] = [lbl for (lbl, _p) in choices]
            # 預設選第一筆（最新）
            if choices:
                self.home_combo.current(0)
                self.home_var.set(choices[0][1])
            else:
                self.home_var.set("")
            self.status_var.set("已載入 HAR（未啟動）。請確認首頁 HTML，然後按「啟動」。")
            self.btn_start.configure(state="normal")

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

            # 如使用者在下拉選了首頁，覆蓋到 ctx
            chosen_home = self.home_var.get().strip()
            cert = self.cert_var.get().strip() if self.show_adv.get() and self.cert_var.get().strip() else None
            key  = self.key_var.get().strip()  if self.show_adv.get() and self.key_var.get().strip()  else None
            if (cert and not key) or (key and not cert):
                from tkinter import messagebox
                messagebox.showerror("錯誤", "若使用 HTTPS，請同時提供憑證與金鑰（PEM）"); return

            def on_ready(scheme):
                self.scheme = scheme
                self.status_var.set(f"伺服器已啟動：{scheme}://localhost:{port}   （主頁：/ ；清單：/__list；偵錯：/__debug）")
                self.btn_start.configure(state="disabled")
                self.btn_stop.configure(state="normal")
                self.btn_open.configure(state="normal")
                webbrowser.open(f"{scheme}://localhost:{port}/")

            def on_error(msg):
                from tkinter import messagebox
                self.status_var.set(f"錯誤：{msg}")
                messagebox.showerror("啟動失敗", msg)

            # 先啟動
            out = run_server(har, port=port, cert=cert, key=key, on_ready=on_ready, on_error=on_error)
            if out is None: return
            self.httpd, self.srv_thread, self.scheme = out[0], out[1], out[2]

            # 如果有選首頁，立即覆寫
            if chosen_home:
                try:
                    # 直接改 handler context
                    HarHandler.ctx['main_path_qs'] = chosen_home
                except Exception:
                    pass

        def on_stop(self):
            if not self.httpd: return
            try:
                self.httpd.shutdown()   # 由於 daemon_threads + timeout，會很快返回
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
    print(f"[HAR Replay v{__version__}] Serving on {scheme}://localhost:{args.port}  (/ , /__list , /__debug)")
    try:
        t.join()
    except KeyboardInterrupt:
        httpd.shutdown(); httpd.server_close()

if __name__ == "__main__":
    main()
