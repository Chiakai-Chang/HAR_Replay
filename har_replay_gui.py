# -*- coding: utf-8 -*-
"""
HAR Replay (GUI + CLI) — main page + HTML URL rewriting
- 自動把 HAR 內第 1 個 HTML 主頁掛在 "/"
- 重寫 HTML 裡的絕對網址到本機，讓資源會打到這台回放伺服器

Created on Mon Feb  3 09:25:57 2025

@author: Chiakai
最後更新：2025-08-19
"""

import argparse
import base64
import json
import os
import ssl
import sys
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit
from pathlib import Path

# ---------- 讀取 HAR & 建索引 ----------

def load_har(har_path):
    with open(har_path, 'rb') as f:
        har = json.load(f)

    entries = har.get('log', {}).get('entries', [])
    maps = {'by_full': {}, 'by_path_qs': {}}
    url_list = []
    origins = set()
    main_path_qs = None  # 我們要掛到 "/"

    for e in entries:
        req = e.get('request', {}) or {}
        res = e.get('response', {}) or {}
        url = req.get('url', '') or ''
        method = (req.get('method') or 'GET').upper()
        u = urlsplit(url)
        path_qs = u.path + (('?' + u.query) if u.query else '')

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

        # 挑第一個 HTML 主頁當 / （GET + 200 + text/html）
        if (main_path_qs is None and method == 'GET' and status == 200):
            ct = headers.get('content-type', '')
            if 'text/html' in ct.lower():
                main_path_qs = path_qs

    return {
        'maps': maps,
        'url_list': url_list,
        'origins': origins,
        'main_path_qs': main_path_qs,
    }

# ---------- 簡單 HTML 重寫（把絕對網址改成本機） ----------

def rewrite_html(body_bytes, server_scheme, server_port, origins):
    # 嘗試以 utf-8 解碼（失敗就不改）
    try:
        html = body_bytes.decode('utf-8')
    except Exception:
        try:
            html = body_bytes.decode('latin-1')
        except Exception:
            return body_bytes

    server_base = f"{server_scheme}://localhost:{server_port}"
    host_base = f"//localhost:{server_port}"

    # 1) https://example.com/... -> http(s)://localhost:PORT/...
    for origin in origins:
        html = html.replace(origin, server_base)

    # 2) //example.com/... -> //localhost:PORT/...
    for origin in origins:
        o = urlsplit(origin)
        html = html.replace(f"//{o.netloc}", host_base)

    # （可選）這裡也能加上 <base href="...">，但多半不必
    return html.encode('utf-8')

# ---------- HTTP Handler ----------

class HarHandler(BaseHTTPRequestHandler):
    ctx = None  # {'maps', 'url_list', 'origins', 'main_path_qs'}
    server_port = None

    def do_GET(self): self._serve()
    def do_POST(self): self._serve()
    def log_message(self, fmt, *args): pass

    def _serve(self):
        ctx = self.ctx
        maps = ctx['maps']
        url_list = ctx['url_list']
        origins = ctx['origins']
        main_path_qs = ctx['main_path_qs']

        method = self.command.upper()
        path_qs = self.path

        # 工具頁
        if path_qs == "/__list":
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.end_headers()
            link_main = '<p><a href="/">開啟主頁（/）</a></p>' if main_path_qs else "<p>未找到 HTML 主頁。</p>"
            html = (
                "<h1>HAR URLs</h1>"
                + link_main +
                "<ul>" + "".join(f"<li>{u}</li>" for u in url_list) + "</ul>"
            )
            self.wfile.write(html.encode("utf-8"))
            return

        # 把 "/" 對應到 HAR 裡的主頁
        if path_qs == "/" and main_path_qs:
            rec = maps['by_path_qs'].get((method, main_path_qs))
        else:
            # 先用 path+query 找
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

        # 如是 HTML，改寫絕對網址成本機
        ct = headers.get('content-type', '')
        is_tls = isinstance(self.server.socket, ssl.SSLSocket)
        scheme = 'https' if is_tls else 'http'
        if 'text/html' in (ct or '').lower():
            body = rewrite_html(body, scheme, self.server_port, origins)

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

    httpd = HTTPServer(("0.0.0.0", int(port)), HarHandler)
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

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("HAR Replay")
            self.geometry("560x260")
            self.resizable(False, False)

            self.httpd = None
            self.srv_thread = None
            self.scheme = "http"

            # HAR
            frm1 = ttk.Frame(self); frm1.pack(fill="x", padx=12, pady=(14,6))
            ttk.Label(frm1, text="HAR 檔案：").pack(side="left")
            self.har_var = tk.StringVar()
            e = ttk.Entry(frm1, textvariable=self.har_var); e.pack(side="left", fill="x", expand=True, padx=6)
            ttk.Button(frm1, text="選擇…", command=self.choose_har).pack(side="left")

            # Port
            frm2 = ttk.Frame(self); frm2.pack(fill="x", padx=12, pady=6)
            ttk.Label(frm2, text="Port：").pack(side="left")
            self.port_var = tk.StringVar(value="3000")
            ttk.Entry(frm2, width=8, textvariable=self.port_var).pack(side="left", padx=(6,0))

            # HTTPS
            frm3 = ttk.Frame(self); frm3.pack(fill="x", padx=12, pady=6)
            self.use_tls = tk.BooleanVar(value=False)
            ttk.Checkbutton(frm3, text="啟用 HTTPS（提供 PEM 憑證/金鑰）", variable=self.use_tls, command=self.toggle_tls).pack(side="left")

            frm4 = ttk.Frame(self); frm4.pack(fill="x", padx=12, pady=(0,6))
            ttk.Label(frm4, text="Cert：").pack(side="left")
            self.cert_var = tk.StringVar()
            self.cert_entry = ttk.Entry(frm4, textvariable=self.cert_var); self.cert_entry.pack(side="left", fill="x", expand=True, padx=6)
            self.btn_cert = ttk.Button(frm4, text="選擇…", command=self.choose_cert); self.btn_cert.pack(side="left")

            frm5 = ttk.Frame(self); frm5.pack(fill="x", padx=12, pady=(0,6))
            ttk.Label(frm5, text="Key：").pack(side="left")
            self.key_var = tk.StringVar()
            self.key_entry = ttk.Entry(frm5, textvariable=self.key_var); self.key_entry.pack(side="left", fill="x", expand=True, padx=6)
            self.btn_key = ttk.Button(frm5, text="選擇…", command=self.choose_key); self.btn_key.pack(side="left")

            self.toggle_tls()

            # 控制
            frm6 = ttk.Frame(self); frm6.pack(fill="x", padx=12, pady=10)
            self.btn_start = ttk.Button(frm6, text="啟動", command=self.on_start); self.btn_start.pack(side="left")
            self.btn_stop  = ttk.Button(frm6, text="停止", command=self.on_stop, state="disabled"); self.btn_stop.pack(side="left", padx=6)
            self.btn_open  = ttk.Button(frm6, text="開啟瀏覽器", command=self.open_browser, state="disabled"); self.btn_open.pack(side="left", padx=6)

            self.status_var = tk.StringVar(value="待命")
            ttk.Label(self, textvariable=self.status_var, foreground="#444").pack(fill="x", padx=12, pady=(0,10))

            self.protocol("WM_DELETE_WINDOW", self.on_close)

        def choose_har(self):
            p = filedialog.askopenfilename(filetypes=[("HAR files", "*.har"), ("All files", "*.*")])
            if p: self.har_var.set(p)

        def choose_cert(self):
            p = filedialog.askopenfilename(filetypes=[("PEM certificate", "*.pem"), ("All files", "*.*")])
            if p: self.cert_var.set(p)

        def choose_key(self):
            p = filedialog.askopenfilename(filetypes=[("PEM private key", "*.pem;*.key"), ("All files", "*.*")])
            if p: self.key_var.set(p)

        def toggle_tls(self):
            enable = self.use_tls.get()
            state = "normal" if enable else "disabled"
            for w in (self.cert_entry, self.btn_cert, self.key_entry, self.btn_key):
                w.configure(state=state)

        def on_start(self):
            if self.httpd: return
            har = self.har_var.get().strip()
            if not har or not os.path.isfile(har):
                messagebox.showerror("錯誤", "請選擇有效的 HAR 檔案"); return
            try:
                port = int(self.port_var.get().strip() or "3000")
            except ValueError:
                messagebox.showerror("錯誤", "Port 必須是數字"); return

            cert = self.cert_var.get().strip() if self.use_tls.get() else None
            key  = self.key_var.get().strip() if self.use_tls.get() else None
            if self.use_tls.get() and (not os.path.isfile(cert) or not os.path.isfile(key)):
                messagebox.showerror("錯誤", "請提供有效的憑證與金鑰（PEM）"); return

            def on_ready(scheme):
                self.scheme = scheme
                self.status_var.set(f"伺服器已啟動：{scheme}://localhost:{port}   （清單：/__list、主頁：/）")
                self.btn_start.configure(state="disabled")
                self.btn_stop.configure(state="normal")
                self.btn_open.configure(state="normal")

            def on_error(msg):
                self.status_var.set(f"錯誤：{msg}")
                messagebox.showerror("啟動失敗", msg)

            out = run_server(har, port=port, cert=cert, key=key, on_ready=on_ready, on_error=on_error)
            if out is None: return
            self.httpd, self.srv_thread, self.scheme = out[0], out[1], out[2]

        def on_stop(self):
            if not self.httpd: return
            try:
                self.httpd.shutdown(); self.httpd.server_close()
            except Exception: pass
            self.httpd = None; self.srv_thread = None
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            self.btn_open.configure(state="disabled")
            self.status_var.set("已停止")

        def open_browser(self):
            if not self.httpd: return
            port = int(self.port_var.get().strip() or "3000")
            webbrowser.open(f"{self.scheme}://localhost:{port}/")

        def on_close(self):
            try: self.on_stop()
            finally: self.destroy()

    App().mainloop()

# ---------- CLI ----------

def main():
    ap = argparse.ArgumentParser(description="Minimal HAR replay server (GUI + CLI)")
    ap.add_argument("--har", help="Path to HAR file")
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--cert", help="PEM cert for HTTPS")
    ap.add_argument("--key", help="PEM key for HTTPS")
    ap.add_argument("--gui", action="store_true", help="Force GUI mode")
    args = ap.parse_args()

    if args.gui or not args.har:
        try: start_gui()
        except KeyboardInterrupt: pass
        return

    out = run_server(args.har, port=args.port, cert=args.cert, key=args.key)
    if out is None: sys.exit(1)
    httpd, t, scheme = out
    print(f"[HAR Replay] Serving on {scheme}://localhost:{args.port}  (list: {scheme}://localhost:{args.port}/  or /__list)")
    try:
        t.join()
    except KeyboardInterrupt:
        httpd.shutdown(); httpd.server_close()

if __name__ == "__main__":
    main()