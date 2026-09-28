"""
ResourceScraper v2.4 — 针对安全审计/密钥泄露检测场景的完整资源收集器

v2.4 速度优化 + 覆盖增强：
- networkidle 超时大幅缩短（3-4s → 2s），静态页更快
- 页面交互 sleep 从 0.8s → 0.3s，滚动间隔从 150ms → 80ms
- Legacy UA 重放超时减半，截图改 domcontentloaded
- 探测请求批次更紧凑（probe_concurrency=20 协程并发）
- BFS worker 空队列退出条件优化，减少无效轮询
"""

import asyncio
import hashlib
import html as _html
import json
import re
from pathlib import Path
from urllib.parse import urlparse, urljoin, urlunparse
from datetime import datetime
from playwright.async_api import async_playwright, Page, BrowserContext

# ── 框架 Manifest 探测路径 ──────────────────────────────────────────────────
MANIFEST_PROBE_PATHS = [
    '/asset-manifest.json', '/build-manifest.json', '/manifest.json',
    '/_next/build-manifest.json', '/_next/react-loadable-manifest.json',
    '/vite-manifest.json', '/.vite/manifest.json', '/static/js/asset-manifest.json',
    '/routes-manifest.json', '/prerender-manifest.json',
    '/_next/static/_ssgManifest.js', '/_next/static/_buildManifest.js',
    '/nitro.json', '/_nuxt/builds/latest.json',
    '/manifest.webmanifest', '/app.webmanifest', '/site.webmanifest',
]

# ── 安全探测字典 ─────────────────────────────────────────────────────────────
SECURITY_PROBE_HIGH = [
    '/.env', '/.env.local', '/.env.production', '/.env.development',
    '/.env.staging', '/.env.backup', '/.env.bak', '/.env.old',
    '/config.js', '/config.json', '/app-config.js', '/runtime-config.js',
    '/env.js', '/env.json', '/settings.js', '/app.config.js',
    '/config/database.yml', '/config/secrets.yml', '/config/credentials.yml',
    '/credentials.json', '/secrets.json', '/private.json',
    '/firebase-credentials.json', '/google-credentials.json',
    '/serviceAccountKey.json',
]

SECURITY_PROBE_BUILD = [
    '/.git/config', '/.git/HEAD', '/.git/COMMIT_EDITMSG',
    '/.git/refs/heads/main', '/.git/refs/heads/master',
    '/.git/logs/HEAD',
    '/webpack.config.js', '/webpack.config.production.js', '/webpack.config.js.bak',
    '/vite.config.js', '/vite.config.ts', '/rollup.config.js',
    '/next.config.js', '/next.config.mjs', '/nuxt.config.js',
    '/babel.config.js', '/tsconfig.json', '/jsconfig.json',
    '/.DS_Store', '/Thumbs.db',
    '/package.json', '/package-lock.json', '/yarn.lock', '/pnpm-lock.yaml',
    '/.npmrc', '/.yarnrc', '/.yarnrc.yml', '/.npmrc.local',
    '/.nvmrc', '/.node-version',
    '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
    '/.dockerignore', '/.gitignore', '/Procfile',
    '/.travis.yml', '/.circleci/config.yml', '/.github/workflows/deploy.yml',
    '/main.js.map', '/app.js.map', '/index.js.map',
    '/bundle.js.map', '/vendor.js.map', '/runtime.js.map',
    '/index.html.bak', '/index.php.bak', '/config.js.bak',
    '/.env.bak', '/.env.old', '/.env.backup',
    '/config.json.bak', '/settings.json.bak',
    '/dist.zip', '/build.zip', '/source.zip', '/backup.zip',
    '/dist.tar.gz', '/www.tar.gz',
    '/schema.graphql', '/schema.gql', '/api.graphql',
    '/api.proto', '/service.proto',
    '/robots.txt', '/sitemap.xml', '/sitemap-index.xml',
    '/_buildManifest.js', '/_ssgManifest.js',
    '/routes-manifest.json', '/prerender-manifest.json',
    '/service-worker.js', '/sw.js', '/mockServiceWorker.js',
    '/firebase-messaging-sw.js', '/push-sw.js',
    '/llms.txt', '/feed.xml', '/rss.xml', '/atom.xml',
    '/llms-full.txt',
    '/decapcms/config.yml', '/admin/config.yml', '/netlify/config.yml',
    '/_cms/config.yml',
    '/pagefind/pagefind-entry.json', '/pagefind/pagefind.js',
    '/pagefind/pagefind-ui.js', '/pagefind/pagefind-ui.css',
    '/pagefind/pagefind-modular-ui.js', '/pagefind/pagefind-modular-ui.css',
    '/pagefind/pagefind-highlight.js',
    '/gulpfile.js', '/Gruntfile.js', '/gruntfile.js',
    '/server.js', '/app.js', '/index.js', '/main.js',
    '/cypress.json', '/cypress.config.js', '/cypress.config.ts',
    '/jest.config.js', '/jest.config.ts', '/vitest.config.js',
    '/playwright.config.js', '/playwright.config.ts',
    '/bower.json', '/.bowerrc',
    '/learn.html', '/demo.html', '/example.html', '/examples.html',
    '/404.html', '/500.html', '/error.html', '/offline.html',
    '/static/development/_buildManifest.js',
    '/static/development/_ssgManifest.js',
    '/cache/next-devtools-config.json', '/cache/config.json',
    '/static/chunks/app/not-found.js',
    '/static/chunks/app/sitemap.xml/route.js',
    '/static/chunks/app/robots.txt/route.js',
    '/react-loadable-manifest.json', '/app-build-manifest.json',
    '/build-manifest.json',
    '/learn.json', '/learn.template.json', '/data.json',
    '/config.yml', '/config.yaml',
]

SECURITY_PROBE_DEBUG = [
    '/api/health', '/api/status', '/api/version', '/health',
    '/status', '/version', '/_health', '/__health',
    '/actuator', '/actuator/health', '/actuator/env', '/actuator/info',
    '/debug', '/debug/vars', '/__debug__',
    '/__webpack_hmr', '/__vite_pong', '/@vite/client',
    '/_next/webpack-hmr', '/webpack-dev-server',
    '/graphql', '/graphql/schema.json', '/api/graphql',
    '/api', '/api/v1', '/api/v2', '/api/config',
    '/api/env', '/api/settings',
    '/old', '/backup', '/temp', '/tmp', '/test',
    '/admin', '/wp-admin', '/phpmyadmin',
]

# ── 黑名单：只排除确定无安全审计价值的纯媒体/字体/二进制 ────────────────
# 注意：SVG 已移出黑名单（可嵌入 <script>/XXE，有安全价值）
# 注意：.zip/.bak 等已移出黑名单（备份泄露高价值）
SKIP_EXTENSIONS = {
    # 栅格图片
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.tiff', '.avif', '.ico',
    # 字体
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    # 纯音视频
    '.mp4', '.mp3', '.webm', '.ogg', '.wav', '.avi', '.mov', '.flac',
    '.aac', '.m4a', '.m4v', '.mkv', '.wmv',
    # 3D图形/HDR（无安全价值）
    '.tga', '.exr', '.hdr', '.dds', '.ktx',
    # 编译型二进制（非 wasm）
    '.exe', '.dll', '.so', '.dylib', '.bin',
    # 系统/IDE 临时文件（低价值）
    '.DS_Store', '.Thumbs.db',
}

# 已知包管理器目录名（出现 2 次即为递归陷阱）
PACKAGE_MANAGER_DIRS = frozenset({
    'bower_components', 'node_modules', 'vendor', 'packages',
    'jspm_packages', 'web_modules',
})


class ResourceScraper:

    def __init__(self, output_dir: str = "scraped_resources",
                 max_crawl_depth: int = 3,
                 max_pages: int = 120,
                 concurrency: int = 10,
                 fetch_timeout_ms: int = 8000,
                 networkidle_short_ms: int = 2000,
                 networkidle_long_ms: int = 3000,
                 sw_wait_seconds: float = 3.0,
                 probe_mode: str = "full",
                 probe_concurrency: int = 20,
                 nonstatic_wait_until: str = "load",
                 nonstatic_goto_timeout_ms: int = 25000,
                 static_goto_timeout_ms: int = 15000,
                 enable_screenshot: bool = True,
                 enable_legacy_ua: bool = True,
                 enable_404_probe: bool = True,
                 enable_service_worker_probe: bool = True):
        self.output_dir     = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.resources      : list[dict] = []
        self.seen_urls      : set[str]   = set()
        self.inflight_urls  : set[str]   = set()
        self.resource_count  = 0
        self.base_url       : str = ''
        self.special_findings: list[dict] = []

        self.max_crawl_depth = max_crawl_depth
        self.max_pages       = max_pages
        self.concurrency     = concurrency
        self.crawl_queue     : list[str] = []
        self.crawled_pages   : set[str]  = set()
        self._resources_lock  = asyncio.Lock()

        self.LISTING_PREFIXES = (
            '/tags/', '/tag/', '/category/', '/categories/',
            '/posts/', '/post/', '/blog/', '/articles/', '/article/',
            '/pages/', '/news/',
        )

        self._is_static_site : bool = False

        # Soft 404 检测：hash（主） + size（副）
        self._index_html_size: int  = 0
        self._index_html_hash: str  = ''
        self._soft404_threshold: int = 50

        self._css_url_fetched: set[str] = set()

        # URL 合法性配置
        self.MAX_PATH_LEN   = 400
        self.MAX_PATH_DEPTH = 12
        self.MAX_SEG_REPEAT = 2   # 通用段重复上限；包管理器目录用独立阈值=2
        self.max_fetch_retries = 1
        # 可调参数：默认偏稳健，避免过度提速导致漏抓
        self.fetch_timeout_ms = fetch_timeout_ms
        self.networkidle_short_ms = networkidle_short_ms
        self.networkidle_long_ms = networkidle_long_ms
        self.sw_wait_seconds = sw_wait_seconds
        self.probe_mode = (probe_mode or "full").lower()
        self.probe_concurrency = max(1, int(probe_concurrency or 20))

        # 导航与后处理开关（默认保持原策略）
        self.nonstatic_wait_until = (nonstatic_wait_until or "load").strip().lower()
        if self.nonstatic_wait_until not in ("load", "domcontentloaded", "networkidle", "commit"):
            self.nonstatic_wait_until = "load"
        self.nonstatic_goto_timeout_ms = int(nonstatic_goto_timeout_ms or 25000)
        self.static_goto_timeout_ms = int(static_goto_timeout_ms or 15000)

        self.enable_screenshot = bool(enable_screenshot)
        self.enable_legacy_ua = bool(enable_legacy_ua)
        self.enable_404_probe = bool(enable_404_probe)
        self.enable_service_worker_probe = bool(enable_service_worker_probe)

    # ────────────────────────────────────────────────────────────────────────
    # URL 工具
    # ────────────────────────────────────────────────────────────────────────

    def _norm(self, url: str) -> str:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, '', '', ''))

    def _is_valid_url(self, url: str) -> bool:
        """
        URL 合法性过滤器 —— 防止 Bower/HTML Imports 相对路径递归陷阱。

        三道检查：
        1. 路径总长度 > MAX_PATH_LEN → 拦截
        2. 路径段数   > MAX_PATH_DEPTH → 拦截
        3a. 包管理器目录（bower_components 等）出现 >= 2 次 → 拦截（严格）
        3b. 任意其他路径段出现 > MAX_SEG_REPEAT 次 → 拦截（宽松）
        """
        try:
            path = urlparse(url).path
        except Exception:
            return False

        if len(path) > self.MAX_PATH_LEN:
            return False

        segments = [s for s in path.split('/') if s]
        if len(segments) > self.MAX_PATH_DEPTH:
            return False

        seg_counts: dict[str, int] = {}
        for seg in segments:
            key = seg.lower()
            seg_counts[key] = seg_counts.get(key, 0) + 1

            # 包管理器目录：出现 2 次立即拦截
            if key in PACKAGE_MANAGER_DIRS and seg_counts[key] >= 2:
                return False

            # 通用段：超过 MAX_SEG_REPEAT 次拦截
            if seg_counts[key] > self.MAX_SEG_REPEAT:
                return False

        return True

    def sanitize_filename(self, url: str, resource_type: str) -> str:
        parsed = urlparse(url)
        parts  = parsed.path.strip('/').split('/')
        name   = parts[-1].split('?')[0] if parts else 'index'
        if not name:
            name = f"{resource_type}_index"
        name = "".join(c if c.isalnum() or c in '._-' else '_' for c in name)
        return name[:200] or 'resource'

    def get_extension(self, content_type: str, url: str, resource_type: str) -> str:
        """
        黑名单模式：URL 中的扩展名只要不在 SKIP_EXTENSIONS 里就收集。
        无扩展名时由 Content-Type 兜底推断。
        返回空串表示该资源应被跳过（黑名单命中）。
        """
        url_part = url.split('/')[-1].split('?')[0]
        if '.' in url_part:
            ext = '.' + url_part.rsplit('.', 1)[-1].lower()
            if ext in SKIP_EXTENSIONS:
                return ''
            return ext

        ct = content_type.lower()
        CT_MAP = {
            'javascript'           : '.js',
            'ecmascript'           : '.js',
            '/css'                 : '.css',
            '/html'                : '.html',
            '/json'                : '.json',
            'application/ld+json'  : '.json',
            '/xml'                 : '.xml',
            'text/xml'             : '.xml',
            '/csv'                 : '.csv',
            'wasm'                 : '.wasm',
            'typescript'           : '.ts',
            '/svg'                 : '.svg',
            'application/rsc'      : '.rsc',
            'application/graphql'  : '.graphql',
            'application/protobuf' : '.proto',
            'application/zip'      : '.zip',
            'application/x-tar'    : '.tar',
            'application/gzip'     : '.gz',
            'text/x-sh'            : '.sh',
            'text/x-python'        : '.py',
            'text/x-php'           : '.php',
            'text/plain'           : '.txt',
        }
        for k, v in CT_MAP.items():
            if k in ct:
                return v
        return {'script': '.js', 'stylesheet': '.css', 'document': '.html',
                'xhr': '.json', 'fetch': '.json'}.get(resource_type, '')

    def _save_content(self, content: bytes, filename: str) -> Path:
        file_path = self.output_dir / filename
        counter = 1
        orig = file_path
        while file_path.exists():
            file_path = orig.with_stem(f"{orig.stem}_v{counter}")
            counter += 1
        file_path.write_bytes(content)
        return file_path

    # ────────────────────────────────────────────────────────────────────────
    # 请求拦截（第一层防护）
    # ────────────────────────────────────────────────────────────────────────

    async def _setup_request_interception(self, context: BrowserContext):
        """
        在浏览器请求发出前拦截病态 URL（递归陷阱防护第一层）。
        - 病态 URL → abort()
        - 跨域请求 → continue()（CDN/字体/GA 正常放行）
        - 同域合法 → continue()
        """
        base_host = urlparse(self.base_url).netloc

        async def handle_route(route, request):
            url = request.url
            try:
                req_host = urlparse(url).netloc
                if req_host and req_host != base_host:
                    await route.continue_()
                    return
            except Exception:
                await route.continue_()
                return

            if not self._is_valid_url(url):
                print(f"  [拦截-递归] {url[:120]}...")
                await route.abort()
                return

            await route.continue_()

        await context.route('**/*', handle_route)

    # ────────────────────────────────────────────────────────────────────────
    # 响应处理（第二层防护）
    # ────────────────────────────────────────────────────────────────────────

    async def _handle_response(self, response, context: BrowserContext):
        norm = ''
        source_page = ''
        try:
            url = response.url

            # 第二层防护：响应回调里再次检查
            if not self._is_valid_url(url):
                return

            norm     = self._norm(url)
            res_type = response.request.resource_type
            status   = response.status
            ct       = response.headers.get('content-type', '')
            ext      = self.get_extension(ct, url, res_type)

            # 记录该资源是从哪个页面触发的，方便日后回溯
            try:
                source_page = getattr(response.frame, "url", "") or ""
            except Exception:
                source_page = ""

            # 黑名单快速跳过（图片/字体/音视频），不占 seen_urls
            if ext == '' and res_type in ('image', 'font', 'media'):
                return

            async with self._resources_lock:
                if norm in self.seen_urls or norm in self.inflight_urls:
                    return
                self.inflight_urls.add(norm)
                self.resource_count += 1
                idx = self.resource_count

            # Soft 404 检测（扩展名期望非 HTML 但返回 text/html）
            is_soft_404 = False
            if status == 200 and 'text/html' in ct:
                url_ext = Path(urlparse(url).path).suffix.lower()
                if url_ext and url_ext not in ('.html', '.htm', '.php', ''):
                    is_soft_404 = True

            rec = {
                'index'           : idx,
                'url'             : url,
                'method'          : response.request.method,
                'status'          : status,
                'resource_type'   : res_type,
                'content_type'    : ct,
                'timestamp'       : datetime.now().isoformat(),
                'request_headers' : dict(response.request.headers),
                'response_headers': dict(response.headers),
            }
            if source_page:
                # 表示是通过哪个页面/导航触发的网络请求
                rec['source_page'] = source_page
            if is_soft_404:
                rec['is_soft_404']     = True
                rec['soft_404_reason'] = f'Expected {Path(urlparse(url).path).suffix}, got text/html'

            if response.ok and not is_soft_404 and response.request.method in ('GET', 'POST'):
                try:
                    content      = await response.body()
                    content_hash = hashlib.md5(content).hexdigest()

                    # 记录首页 hash/size（首次 document 响应）
                    is_index_page = (self._index_html_size == 0 and res_type == 'document')
                    if is_index_page:
                        self._index_html_size = len(content)
                        self._index_html_hash = content_hash

                    # Hash-based soft 404 二次验证（跳过首页自身）
                    if (not is_soft_404
                            and not is_index_page
                            and 'text/html' in ct
                            and self._index_html_hash
                            and content_hash == self._index_html_hash):
                        # 重要：对 SPA/History Fallback 站点而言，不同路由可能返回同一份 index.html，
                        # 这并不意味着“资源不存在”。对 document（页面导航）保留记录与落盘，
                        # 仅对“期望非 HTML 的资源”判定为 Soft 404。
                        url_path = urlparse(url).path
                        url_ext  = Path(url_path).suffix.lower()
                        is_html_like_path = (url_path.endswith('/')
                                             or url_ext in ('', '.html', '.htm', '.php'))

                        if res_type == 'document' and is_html_like_path:
                            rec['spa_shell'] = True
                            rec['spa_shell_reason'] = 'Content hash matches index.html (SPA shell)'
                        else:
                            is_soft_404 = True
                            rec['is_soft_404']     = True
                            rec['soft_404_reason'] = 'Content hash matches index.html (SPA fallback)'

                    if is_soft_404:
                        async with self._resources_lock:
                            self.seen_urls.add(norm)
                            self.resources.append(rec)
                        return

                    filename = self.sanitize_filename(url, res_type)
                    if ext and not filename.endswith(ext):
                        filename += ext
                    file_path         = self._save_content(content, filename)
                    rec['saved_path'] = str(file_path)
                    rec['size_bytes'] = len(content)
                    file_path.with_suffix(file_path.suffix + '.meta.json').write_text(
                        json.dumps({**rec, 'saved_as': file_path.name}, indent=2, ensure_ascii=False),
                        encoding='utf-8'
                    )
                    if ext == '.js':
                        await self._handle_js_sourcemap(content, url, context)
                        await self._extract_chunks_from_js(content, url, context)
                    if ext == '.css':
                        await self._parse_css_url_refs(content, url, context)
                    if ext in ('.html', '') or res_type == 'document':
                        fetch_list = self._scan_html_injections(content, url)
                        if fetch_list:
                            asyncio.ensure_future(asyncio.gather(*[
                                self._fetch_and_save(u, context, 'html-static-ref',
                                                     f'<script/link> in {url[:60]}')
                                for u in fetch_list
                            ]))
                    if 'manifest' in url.lower() and ext == '.json':
                        await self._parse_manifest_json(content, url, context)
                except Exception as e:
                    rec['download_error'] = str(e)

            async with self._resources_lock:
                self.seen_urls.add(norm)
                self.resources.append(rec)
        except Exception:
            pass
        finally:
            if norm:
                async with self._resources_lock:
                    self.inflight_urls.discard(norm)

    # ────────────────────────────────────────────────────────────────────────
    # JS 处理
    # ────────────────────────────────────────────────────────────────────────

    async def _handle_js_sourcemap(self, content: bytes, js_url: str,
                                    context: BrowserContext):
        text = content.decode('utf-8', errors='ignore')
        m = re.search(r'//# sourceMappingURL=([^\s]+)', text[-1024:])
        if m:
            map_ref = m.group(1).strip()
            base    = js_url.rsplit('/', 1)[0]
            map_url = urljoin(base + '/', map_ref.split('?')[0])
            if self._is_valid_url(map_url):
                await self._fetch_and_save(map_url, context, 'source-map',
                                           f'sourceMappingURL in {js_url}')
        blind = js_url.split('?')[0] + '.map'
        if self._is_valid_url(blind) and self._norm(blind) not in self.seen_urls:
            await self._fetch_and_save(blind, context, 'source-map-blind',
                                       f'blind guess from {js_url}')

    async def _extract_chunks_from_js(self, content: bytes, js_url: str,
                                       context: BrowserContext):
        text        = content.decode('utf-8', errors='ignore')
        chunk_set   = set()
        chunk_set.update(re.findall(r'["\']([a-f0-9]{8,16}\.chunk\.js)["\']', text))
        # 兼容 static import: from "./chunk-XXXX.js" / "./chunk-XXXX.js"
        chunk_set.update(re.findall(r'["\'](?:\.\/|/)?(chunk-[A-Za-z0-9_\-]+\.js)["\']', text))
        chunks      = list(chunk_set)
        parsed      = urlparse(js_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        pub_path_m  = re.search(r'publicPath\s*[:=]\s*["\']([^"\']+)["\']', text)
        pub_path    = pub_path_m.group(1) if pub_path_m else ''

        for chunk in chunks:
            for prefix in [pub_path, 'static/js/', 'assets/', '_next/static/chunks/', '']:
                url = urljoin(base_origin + '/', (prefix + chunk).lstrip('/'))
                if self._is_valid_url(url) and self._norm(url) not in self.seen_urls:
                    ok = await self._fetch_and_save(url, context, 'dynamic-chunk', 'chunk map')
                    if ok:
                        break

        for m in re.finditer(r'import\(["\'](\./[^"\']+\.(?:js|mjs))["\']', text):
            url = urljoin(js_url.rsplit('/', 1)[0] + '/', m.group(1))
            if self._is_valid_url(url):
                await self._fetch_and_save(url, context, 'vite-dynamic-chunk',
                                           'vite dynamic import')

        # i18n JSON
        i18n_patterns = [
            r'["\']([^"\']*(?:locale|locales|i18n|lang|languages?|translations?|nls)/[^"\']+\.json)["\']',
            r'["\']([^"\']*[/\\][a-z]{2}(?:-[A-Z]{2})?\.json)["\']',
        ]
        for pat in i18n_patterns:
            for m in re.finditer(pat, text):
                ref = m.group(1).strip()
                url = (urljoin(base_origin, ref) if ref.startswith('/')
                       else urljoin(js_url.rsplit('/', 1)[0] + '/', ref))
                if self._is_valid_url(url):
                    await self._fetch_and_save(url, context, 'i18n-json',
                                               f'i18n ref in {js_url[-50:]}')

        # Service Worker 路径提取
        for m in re.finditer(
            r'serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']',
            text
        ):
            sw_ref = m.group(1).strip().split('?')[0]
            sw_url = (urljoin(base_origin, sw_ref) if sw_ref.startswith('/')
                      else urljoin(js_url.rsplit('/', 1)[0] + '/', sw_ref))
            if self._is_valid_url(sw_url):
                await self._fetch_and_save(sw_url, context, 'service-worker',
                                           f'serviceWorker.register in {js_url[-50:]}')

        # workbox importScripts
        for m in re.finditer(r'importScripts\s*\(["\']([^"\']+)["\']\)', text):
            ref    = m.group(1).strip().split('?')[0]
            sw_url = (urljoin(base_origin, ref) if ref.startswith('/')
                      else urljoin(js_url.rsplit('/', 1)[0] + '/', ref))
            if self._is_valid_url(sw_url):
                await self._fetch_and_save(sw_url, context, 'sw-importscripts',
                                           f'importScripts in {js_url[-50:]}')

        # WebAssembly 模块引用（静态 import / 动态 import / import.meta.url）
        wasm_patterns = [
            # import init, { fn } from "./processor.wasm";
            r'import\s+[^"\']+\s+from\s+["\']([^"\']+\.wasm)["\']',
            # import("./processor.wasm")
            r'import\(\s*["\']([^"\']+\.wasm)["\']\s*\)',
            # new URL("./processor.wasm", import.meta.url)
            r'new\s+URL\(\s*["\']([^"\']+\.wasm)["\']\s*,\s*import\.meta\.url\s*\)',
        ]
        for pat in wasm_patterns:
            for m in re.finditer(pat, text):
                ref = m.group(1).strip().split('?')[0]
                if not ref:
                    continue
                wasm_url = (
                    urljoin(base_origin, ref) if ref.startswith('/')
                    else urljoin(js_url.rsplit('/', 1)[0] + '/', ref)
                )
                if self._is_valid_url(wasm_url):
                    await self._fetch_and_save(
                        wasm_url,
                        context,
                        'wasm-module',
                        f'wasm import in {js_url[-80:]}',
                    )

        # 兜底：任意字符串字面量中出现 *.wasm（例如 fetch("/x.wasm")）
        generic_wasm_refs = set()
        for m in re.finditer(r'["\']([^"\']+\.wasm)["\']', text):
            ref = m.group(1).strip().split('?')[0]
            if not ref:
                continue
            generic_wasm_refs.add(ref)
        for ref in generic_wasm_refs:
            wasm_url = (
                urljoin(base_origin, ref) if ref.startswith('/')
                else urljoin(js_url.rsplit('/', 1)[0] + '/', ref)
            )
            if self._is_valid_url(wasm_url):
                await self._fetch_and_save(
                    wasm_url,
                    context,
                    'wasm-module',
                    f'wasm string literal in {js_url[-80:]}',
                )


    # ────────────────────────────────────────────────────────────────────────
    # CSS 处理
    # ────────────────────────────────────────────────────────────────────────

    async def _parse_css_url_refs(self, content: bytes, css_url: str,
                                   context: BrowserContext):
        text        = content.decode('utf-8', errors='ignore')
        parsed      = urlparse(css_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        for m in re.finditer(r'url\(["\']?([^"\')\s]+)["\']?\)', text):
            ref = m.group(1).strip()
            if ref.startswith('data:') or not ref:
                continue
            ext = Path(ref.split('?')[0]).suffix.lower()
            if ext in SKIP_EXTENSIONS:
                continue
            url = (urljoin(base_origin, ref) if ref.startswith('/')
                   else urljoin(css_url.rsplit('/', 1)[0] + '/', ref))
            url = url.split('?')[0]
            if self._is_valid_url(url) and url not in self._css_url_fetched:
                self._css_url_fetched.add(url)
                await self._fetch_and_save(url, context, 'css-url-ref',
                                           f'CSS url() in {css_url[-50:]}')

        # CSS source map
        m = re.search(r'/\*# sourceMappingURL=([^\s*]+)', text[-512:])
        if m:
            map_ref = m.group(1).strip()
            map_url = urljoin(css_url.rsplit('/', 1)[0] + '/', map_ref.split('?')[0])
            if self._is_valid_url(map_url):
                await self._fetch_and_save(map_url, context, 'source-map',
                                           f'sourceMappingURL in {css_url}')
        blind = css_url.split('?')[0] + '.map'
        if self._is_valid_url(blind) and self._norm(blind) not in self.seen_urls:
            await self._fetch_and_save(blind, context, 'source-map-blind',
                                       f'blind guess from {css_url}')

    # ────────────────────────────────────────────────────────────────────────
    # HTML 注入检测 & 链接提取（第三层防护：入队前检查）
    # ────────────────────────────────────────────────────────────────────────

    def _scan_html_injections(self, content: bytes, url: str) -> list:
        text        = content.decode('utf-8', errors='ignore')
        base_host   = urlparse(self.base_url).netloc
        base_origin = f"{urlparse(self.base_url).scheme}://{base_host}"
        fetch_urls  : list = []

        # SSR 数据注入检测
        nd = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', text, re.S)
        if nd:
            self.special_findings.append({
                'type': 'SSR_DATA_INJECTION', 'frame': 'Next.js', 'url': url,
                'detail': '__NEXT_DATA__', 'snippet': nd.group(1)[:500],
            })
        nuxt = re.search(r'window\.__NUXT__\s*=\s*(\{.+?\})\s*;', text, re.S)
        if nuxt:
            self.special_findings.append({
                'type': 'SSR_DATA_INJECTION', 'frame': 'Nuxt.js', 'url': url,
                'detail': 'window.__NUXT__', 'snippet': nuxt.group(1)[:500],
            })
        alpine_hits = re.findall(r'x-data=["\'](\{[^"\']{15,})["\']', text)
        if alpine_hits:
            self.special_findings.append({
                'type': 'INLINE_LOGIC', 'frame': 'Alpine.js', 'url': url,
                'detail': f'x-data ({len(alpine_hits)} 处)', 'snippets': alpine_hits[:3],
            })

        def _resolve(href: str) -> str:
            href = _html.unescape(href.strip()).split('?')[0].split('#')[0]
            if not href or href.startswith(('mailto:', 'javascript:', 'data:')):
                return ''
            if href.startswith('//'):
                href = urlparse(base_origin).scheme + ':' + href
            if href.startswith('/'):
                full = base_origin + href
            elif href.startswith('http'):
                if urlparse(href).netloc != base_host:
                    return ''
                full = urlunparse((*urlparse(href)[:3], '', '', ''))
            else:
                full = urljoin(url.rsplit('/', 1)[0] + '/', href)
            if not self._is_valid_url(full):
                return ''
            return full

        def _enqueue_page(href: str):
            full = _resolve(href)
            if not full:
                return
            if self._norm(full) not in self.crawled_pages:
                path = urlparse(full).path
                if any(path.startswith(p) for p in self.LISTING_PREFIXES):
                    self.crawl_queue.insert(0, full)
                else:
                    self.crawl_queue.append(full)

        def _enqueue_resource(href: str):
            full = _resolve(href)
            if full and self._norm(full) not in self.seen_urls:
                fetch_urls.append(full)

        # <script src>
        for m in re.finditer(r'<script[^>]+src=["\']((?!data:)[^"\']+)["\']', text, re.I):
            _enqueue_resource(m.group(1))

        # <link rel="stylesheet">
        for m in re.finditer(
            r'<link[^>]+rel=["\']stylesheet["\'][^>]*href=["\']((?!data:)[^"\']+)["\']',
            text, re.I
        ):
            _enqueue_resource(m.group(1))

        # <link rel="icon">
        for m in re.finditer(
            r'<link[^>]+rel=["\'][^"\']*(?:shortcut\s+)?icon[^"\']*["\'][^>]*href=["\']((?!data:)[^"\']+)["\']',
            text, re.I
        ):
            _enqueue_resource(m.group(1))

        # <link rel="manifest">
        for m in re.finditer(
            r'<link[^>]+rel=["\'][^"\']*manifest[^"\']*["\'][^>]*href=["\']((?!data:)[^"\']+)["\']',
            text, re.I
        ):
            _enqueue_page(m.group(1))

        # <script nomodule src>
        for m in re.finditer(r'<script[^>]+nomodule[^>]*src=["\']((?!data:)[^"\']+)["\']', text, re.I):
            _enqueue_resource(m.group(1))

        # <link rel="import"> (Polymer/Bower)
        for m in re.finditer(
            r'<link[^>]+rel=["\']import["\'][^>]*href=["\']((?!data:)[^"\']+)["\']',
            text, re.I
        ):
            _enqueue_page(m.group(1))

        # 同域 <a>
        for m in re.finditer(r'<a\s[^>]*href=["\']((?![#?])[^"\']+)["\']', text, re.I):
            _enqueue_page(m.group(1))

        return fetch_urls

    # ────────────────────────────────────────────────────────────────────────
    # Manifest JSON
    # ────────────────────────────────────────────────────────────────────────

    async def _parse_manifest_json(self, content: bytes, manifest_url: str,
                                    context: BrowserContext):
        try:
            data   = json.loads(content)
            base   = urlparse(manifest_url)
            origin = f"{base.scheme}://{base.netloc}"
            for ref in self._extract_urls_from_json(data):
                url = (urljoin(origin, ref) if ref.startswith('/')
                       else urljoin(manifest_url, ref))
                if self._is_valid_url(url):
                    await self._fetch_and_save(url, context, 'manifest-ref',
                                               f'manifest {manifest_url}')
        except Exception:
            pass

    def _extract_urls_from_json(self, data, depth: int = 0) -> list[str]:
        if depth > 6:
            return []
        results = []
        if isinstance(data, str):
            s = data.strip()
            # 通用 URL/路径（以 / 或 . 开头，带扩展名）
            if re.match(r'^[/.].*\.\w{2,5}$', s):
                results.append(s)
            # WebAssembly 专门处理：任意包含 .wasm 的字符串都视为候选
            elif '.wasm' in s:
                results.append(s)
        elif isinstance(data, dict):
            for v in data.values():
                results.extend(self._extract_urls_from_json(v, depth + 1))
        elif isinstance(data, list):
            for item in data:
                results.extend(self._extract_urls_from_json(item, depth + 1))
        return results

    # ────────────────────────────────────────────────────────────────────────
    # 主动拉取
    # ────────────────────────────────────────────────────────────────────────

    async def _fetch_and_save(self, url: str, context: BrowserContext,
                               category: str = '', note: str = '') -> bool:
        if not self._is_valid_url(url):
            return False
        norm = self._norm(url)
        async with self._resources_lock:
            if norm in self.seen_urls or norm in self.inflight_urls:
                return False
            self.inflight_urls.add(norm)
        try:
            for attempt in range(self.max_fetch_retries + 1):
                try:
                    resp = await context.request.get(url, timeout=self.fetch_timeout_ms)
                    if not resp.ok:
                        continue

                    content    = await resp.body()
                    ct         = resp.headers.get('content-type', '')
                    url_ext    = Path(urlparse(url).path).suffix.lower()
                    is_soft_404 = (
                        'text/html' in ct
                        and url_ext
                        and url_ext not in ('.html', '.htm', '.php', '')
                    )
                    if not is_soft_404 and 'text/html' in ct and self._index_html_hash:
                        if hashlib.md5(content).hexdigest() == self._index_html_hash:
                            is_soft_404 = True
                    elif not is_soft_404 and self._index_html_size > 0 and 'text/html' in ct:
                        if abs(len(content) - self._index_html_size) <= self._soft404_threshold:
                            is_soft_404 = True

                    if is_soft_404:
                        async with self._resources_lock:
                            self.inflight_urls.discard(norm)
                            self.seen_urls.add(norm)
                            self.resource_count += 1
                            self.resources.append({
                                'index'          : self.resource_count,
                                'url'            : url,
                                'method'         : 'GET',
                                'status'         : resp.status,
                                'resource_type'  : category,
                                'content_type'   : ct,
                                'size_bytes'     : len(content),
                                'note'           : note,
                                'timestamp'      : datetime.now().isoformat(),
                                'is_soft_404'    : True,
                                'soft_404_reason': f'Expected {url_ext}, got text/html',
                            })
                        return False

                    ext      = self.get_extension(ct, url, 'fetch')
                    filename = self.sanitize_filename(url, category)
                    if ext and not filename.endswith(ext):
                        filename += ext
                    file_path = self._save_content(content, filename)
                    async with self._resources_lock:
                        self.inflight_urls.discard(norm)
                        self.seen_urls.add(norm)
                        self.resource_count += 1
                        self.resources.append({
                            'index'        : self.resource_count,
                            'url'          : url,
                            'method'       : 'GET',
                            'status'       : resp.status,
                            'resource_type': category,
                            'content_type' : ct,
                            'size_bytes'   : len(content),
                            'saved_path'   : str(file_path),
                            'note'         : note,
                            # 记录资源的主要获取路径/来源信息，便于回溯
                            'origin'       : note or category or 'manual-fetch',
                            'timestamp'    : datetime.now().isoformat(),
                        })
                    if ext == '.js':
                        await self._handle_js_sourcemap(content, url, context)
                        await self._extract_chunks_from_js(content, url, context)
                    if ext == '.css':
                        await self._parse_css_url_refs(content, url, context)
                    return True
                except Exception:
                    if attempt >= self.max_fetch_retries:
                        break
                    await asyncio.sleep(0.2 * (attempt + 1))
            return False
        finally:
            async with self._resources_lock:
                self.inflight_urls.discard(norm)

    # ────────────────────────────────────────────────────────────────────────
    # 页面访问
    # ────────────────────────────────────────────────────────────────────────

    async def _is_static_page(self, url: str) -> bool:
        if self._is_static_site:
            return True
        return any(urlparse(url).path.startswith(p) for p in self.LISTING_PREFIXES)

    async def _visit_page(self, page: Page, context: BrowserContext,
                          url: str, is_first_page: bool = False):
        norm = self._norm(url)
        if norm in self.crawled_pages:
            return
        self.crawled_pages.add(norm)

        static_mode = await self._is_static_page(url) and not is_first_page

        try:
            if static_mode:
                await page.goto(url, wait_until='domcontentloaded', timeout=self.static_goto_timeout_ms)
                try:
                    await page.wait_for_load_state('networkidle', timeout=self.networkidle_short_ms)
                except Exception:
                    pass
            else:
                await page.goto(url, wait_until=self.nonstatic_wait_until, timeout=self.nonstatic_goto_timeout_ms)
                try:
                    await page.wait_for_load_state('networkidle', timeout=self.networkidle_short_ms)
                except Exception:
                    pass

            # 只有首页才执行懒加载滚动和交互点击
            if is_first_page:
                # 懒加载滚动：触发页面内的动态加载
                try:
                    await page.evaluate("""async () => {
                        const sleep = ms => new Promise(r => setTimeout(r, ms));
                        for (let i = 1; i <= 4; i++) {
                            window.scrollTo(0, document.body.scrollHeight * (i/4));
                            await sleep(80);
                        }
                        window.scrollTo(0, 0);
                    }""")
                    await asyncio.sleep(0.3)
                except Exception:
                    pass

                # 点击搜索框
                await self._trigger_search_widget(page, context)

                # 点击导航元素
                await self._click_interactive_elements(page)

                try:
                    await page.wait_for_load_state('networkidle', timeout=self.networkidle_long_ms)
                except Exception:
                    pass

            try:
                html_content = await page.content()
                fetch_list = self._scan_html_injections(html_content.encode(), url)
                if fetch_list:
                    await asyncio.gather(*[
                        self._fetch_and_save(u, context, 'html-static-ref',
                                             f'<script/link> in {url[:60]}')
                        for u in fetch_list
                    ])
            except Exception:
                pass

        except Exception as e:
            print(f"  [页面访问] 警告: {url[:60]} — {e}")

    async def _trigger_search_widget(self, page: Page, context: BrowserContext):
        selectors = [
            'input[type="search"]', 'input[placeholder*="search" i]',
            'input[placeholder*="搜索" i]', 'button[aria-label*="search" i]',
            '[data-pagefind-ui]', '.search-toggle', '.search-btn', '#search-button',
            '[class*="search"][role="button"]',
        ]
        for sel in selectors:
            try:
                el = await page.query_selector(sel)
                if el:
                    await el.click(timeout=1000)
                    await asyncio.sleep(0.3)
                    try:
                        await page.wait_for_load_state('networkidle', timeout=self.networkidle_short_ms)
                    except Exception:
                        pass
                    print(f"  [搜索框] 触发: {sel}")
                    break
            except Exception:
                pass

    async def _click_interactive_elements(self, page: Page):
        selectors = [
            'nav a', '[role="navigation"] a', '.sidebar a', '.menu a',
            '.nav-item a', '[role="menuitem"]', '.el-menu-item', '.ant-menu-item',
        ]
        clicked   = 0
        base_host = urlparse(self.base_url).netloc
        for selector in selectors:
            if clicked >= 15:
                break
            try:
                elements = await page.query_selector_all(selector)
                for el in elements[:4]:
                    try:
                        href = await el.get_attribute('href')
                        if href and not href.startswith('http'):
                            await el.click(timeout=1500)
                            await asyncio.sleep(0.3)
                            clicked += 1
                        elif href and urlparse(href).netloc == base_host:
                            await el.click(timeout=1500)
                            await asyncio.sleep(0.3)
                            clicked += 1
                    except Exception:
                        pass
            except Exception:
                pass
        if clicked:
            print(f"  [点击交互] 触发了 {clicked} 个导航元素")
            await asyncio.sleep(0.5)

    # ────────────────────────────────────────────────────────────────────────
    # BFS 并行爬取
    # ────────────────────────────────────────────────────────────────────────

    async def _recursive_crawl(self, context: BrowserContext,
                                start_url: str, max_depth: int):
        bfs_queue: list[tuple[str, int]] = [(start_url, 0)]
        for pre_url in list(self.crawl_queue):
            n = self._norm(pre_url)
            if n != self._norm(start_url) and self._is_valid_url(pre_url):
                bfs_queue.append((pre_url, 1))
        self.crawl_queue.clear()

        visited   = set()
        sem       = asyncio.Semaphore(self.concurrency)
        page_pool : list[Page] = []
        pool_lock = asyncio.Lock()

        for _ in range(self.concurrency):
            p = await context.new_page()
            p.on('response', lambda r, ctx=context: asyncio.ensure_future(
                self._handle_response(r, ctx)))
            page_pool.append(p)

        async def acquire_page() -> Page:
            async with pool_lock:
                return page_pool.pop() if page_pool else await context.new_page()

        async def release_page(p: Page):
            async with pool_lock:
                page_pool.append(p)

        bfs_lock     = asyncio.Lock()
        pending      = asyncio.Queue()
        active_count = 0
        active_lock  = asyncio.Lock()

        for item in bfs_queue:
            await pending.put(item)

        async def worker():
            nonlocal active_count
            idle_rounds = 0
            while True:
                try:
                    url, depth = pending.get_nowait()
                    idle_rounds = 0
                except asyncio.QueueEmpty:
                    async with active_lock:
                        if active_count == 0:
                            return
                    idle_rounds += 1
                    if idle_rounds > 30:
                        return
                    await asyncio.sleep(0.05)
                    continue

                # ── 关键修复：active_count++ 必须紧跟 get_nowait()，
                # 在任何 await 之前，防止其他 worker 误判"队列空+无活跃=退出"
                async with active_lock:
                    active_count += 1

                norm = self._norm(url)
                async with bfs_lock:
                    if norm in visited or len(self.crawled_pages) >= self.max_pages:
                        async with active_lock:
                            active_count -= 1
                        pending.task_done()
                        continue
                    visited.add(norm)

                is_first   = (norm == self._norm(start_url))
                path       = urlparse(url).path
                is_listing = any(path.startswith(p) for p in self.LISTING_PREFIXES)
                eff_depth  = max_depth + 1 if is_listing else max_depth

                async with sem:
                    pg = await acquire_page()
                    try:
                        print(f"  [爬取 深度{depth}{'*' if is_listing else ''}"
                              f" 已访问{len(self.crawled_pages)}页] {url[:70]}")
                        before = len(self.crawl_queue)
                        await self._visit_page(pg, context, url, is_first_page=is_first)
                        if depth < eff_depth:
                            async with bfs_lock:
                                for link in self.crawl_queue[before:]:
                                    ln = self._norm(link)
                                    if ln not in visited and self._is_valid_url(link):
                                        await pending.put((link, depth + 1))
                    finally:
                        await release_page(pg)

                async with active_lock:
                    active_count -= 1
                pending.task_done()

        workers = [asyncio.ensure_future(worker()) for _ in range(self.concurrency)]
        await asyncio.gather(*workers)

        async with pool_lock:
            for p in page_pool:
                try:
                    await p.close()
                except Exception:
                    pass
            page_pool.clear()

        print(f"  [爬取完成] 共访问 {len(self.crawled_pages)} 个页面 | "
              f"已收集资源 {len(self.resources)} 个")

    # ────────────────────────────────────────────────────────────────────────
    # Sitemap
    # ────────────────────────────────────────────────────────────────────────

    async def _try_sitemap(self, base_origin: str,
                            context: BrowserContext) -> list[str]:
        # sitemap-index.xml 优先，sitemap-0.xml 作为直接候选（不通过 index）
        sitemap_candidates = ['/sitemap-index.xml', '/sitemap.xml', '/sitemap-0.xml']
        collected_urls: list[str] = []
        fetched_sitemaps: set[str] = set()   # 防止重复 fetch 同一 sitemap
        base_host = urlparse(base_origin).netloc

        async def _fetch_sitemap(sm_url: str, depth: int = 0):
            if depth > 2 or sm_url in fetched_sitemaps:
                return
            fetched_sitemaps.add(sm_url)
            try:
                resp = await context.request.get(sm_url, timeout=8000)
                if not resp.ok:
                    return
                ct = resp.headers.get('content-type', '')
                if 'html' in ct and depth == 0:
                    return   # 顶层返回 html = soft 404，跳过
                body = await resp.body()
                text = body.decode('utf-8', errors='ignore')

                # 保存 sitemap 文件本身（无论是 index 还是子 sitemap）
                await self._fetch_and_save(sm_url, context, 'sitemap', f'sitemap depth={depth}')

                all_locs = re.findall(r'<loc>\s*(https?://[^\s<]+)\s*</loc>', text)
                for loc in all_locs:
                    loc = loc.strip().split('?')[0]
                    if urlparse(loc).netloc != base_host:
                        continue
                    if loc.lower().endswith('.xml'):
                        # 子 sitemap：递归解析，并保存文件
                        await _fetch_sitemap(loc, depth + 1)
                    else:
                        collected_urls.append(loc)
            except Exception:
                pass

        for path in sitemap_candidates:
            before = len(collected_urls)
            await _fetch_sitemap(base_origin + path, depth=0)
            if len(collected_urls) > before:
                print(f"  [sitemap] {path} → 发现 {len(collected_urls)} 个页面 URL")
                break

        seen, result = set(), []
        for u in collected_urls:
            n = self._norm(u)
            if n not in seen:
                seen.add(n)
                result.append(u)
        return result

    # ────────────────────────────────────────────────────────────────────────
    # 主入口
    # ────────────────────────────────────────────────────────────────────────

    async def scrape(self, url: str):
        self.base_url = url
        print(f"\n{'='*70}\n  ResourceScraper v2.3  →  {url}\n"
              f"  并发: {self.concurrency} tabs\n{'='*70}\n")

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=['--disable-blink-features=AutomationControlled',
                      '--disable-web-security', '--no-sandbox']
            )
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent=(
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/122.0.0.0 Safari/537.36'
                ),
                ignore_https_errors=True,
            )

            print("[0-pre] 注册请求拦截器（递归陷阱防护）...")
            await self._setup_request_interception(context)

            base_origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

            print("[0] 尝试解析 sitemap...")
            sitemap_urls = await self._try_sitemap(base_origin, context)
            if sitemap_urls:
                print(f"  → 发现 {len(sitemap_urls)} 个页面 URL，注入爬取队列")
                if len(sitemap_urls) <= 10:
                    for su in sitemap_urls:
                        print(f"    {su}")
                else:
                    for su in sitemap_urls[:5]:
                        print(f"    {su}")
                    print(f"    ... 共 {len(sitemap_urls)} 个")
                self._is_static_site = True
                injected = 0
                for su in sitemap_urls:
                    if self._is_valid_url(su) and self._norm(su) not in self.crawled_pages:
                        self.crawl_queue.append(su)
                        injected += 1
                print(f"  → 有效注入 BFS 队列: {injected} 个")
            else:
                print("  → 未找到 sitemap，使用常规递归爬取")

            print(f"[1] 并行爬取（{self.concurrency} tabs，"
                  f"深度 {self.max_crawl_depth}，最多 {self.max_pages} 页）...")
            t0 = datetime.now()
            await self._recursive_crawl(context, url, self.max_crawl_depth)
            print(f"  → 爬取耗时: {(datetime.now()-t0).total_seconds():.1f}s")

            print("[2/3] 并发探测：Manifest + 安全高价值 + 构建遗留物 + 调试端点...")
            t1 = datetime.now()
            build_probe_paths = SECURITY_PROBE_BUILD
            debug_probe_paths = SECURITY_PROBE_DEBUG
            if self.probe_mode == "lite":
                build_probe_paths = SECURITY_PROBE_BUILD[:25]
                debug_probe_paths = []
            elif self.probe_mode in ("balanced", "standard"):
                build_probe_paths = SECURITY_PROBE_BUILD[:60]
                debug_probe_paths = SECURITY_PROBE_DEBUG[:20]
            probe_sem = asyncio.Semaphore(self.probe_concurrency)
            async def _throttled_probe(u, ctx, cat, note):
                async with probe_sem:
                    return await self._fetch_and_save(u, ctx, cat, note)
            probe_tasks = (
                [_throttled_probe(base_origin + p, context, 'manifest-probe', p)
                 for p in MANIFEST_PROBE_PATHS] +
                [_throttled_probe(base_origin + p, context, 'security-high', p)
                 for p in SECURITY_PROBE_HIGH] +
                [_throttled_probe(base_origin + p, context, 'security-build', p)
                 for p in build_probe_paths] +
                [_throttled_probe(base_origin + p, context, 'security-debug', p)
                 for p in debug_probe_paths]
            )
            await asyncio.gather(*probe_tasks)
            print(f"  → 探测耗时: {(datetime.now()-t1).total_seconds():.1f}s")

            print("[3b] 后处理：动态清单解析 + Legacy UA 重放...")

            # Nuxt 3: /_nuxt/builds/latest.json → meta/[id].json
            nuxt_latest = next(
                (r for r in self.resources
                 if '/_nuxt/builds/latest.json' in r.get('url', '')
                 and r.get('saved_path')),
                None
            )
            if nuxt_latest:
                try:
                    data     = json.loads(Path(nuxt_latest['saved_path']).read_text())
                    build_id = data.get('id') or data.get('buildId')
                    if build_id:
                        meta_url = f"{base_origin}/_nuxt/builds/meta/{build_id}.json"
                        ok = await self._fetch_and_save(meta_url, context,
                                                        'nuxt-builds-meta', 'nuxt builds meta')
                        if ok:
                            print(f"  [Nuxt] 抓取到 builds/meta/{build_id}.json")
                except Exception:
                    pass

            # Pagefind entry JSON 解析
            pagefind_entry = next(
                (r for r in self.resources
                 if '/pagefind/pagefind-entry.json' in r.get('url', '')
                 and r.get('saved_path')),
                None
            )
            if pagefind_entry:
                try:
                    data    = json.loads(Path(pagefind_entry['saved_path']).read_text())
                    pf_base = base_origin + '/pagefind/'
                    for key in ('wasm_url', 'index_chunks', 'filter_chunks',
                                'search_chunks', 'ranking_chunks'):
                        val = data.get(key)
                        if isinstance(val, str):
                            await self._fetch_and_save(urljoin(pf_base, val),
                                                       context, 'pagefind', key)
                        elif isinstance(val, list):
                            for item in val[:20]:
                                await self._fetch_and_save(urljoin(pf_base, item),
                                                           context, 'pagefind', key)
                    print("  [Pagefind] 解析 pagefind-entry.json 完成")
                except Exception:
                    pass

            # Legacy Bundle 重放（IE11 UA）—— 仅在未检测到 legacy 资源时执行
            any_legacy = any('/legacy/' in r.get('url', '') for r in self.resources)
            if self.enable_legacy_ua and (not any_legacy):
                legacy_ua = 'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko'
                try:
                    legacy_ctx = await browser.new_context(user_agent=legacy_ua,
                                                           viewport={'width': 1280, 'height': 800})
                    legacy_pg  = await legacy_ctx.new_page()
                    legacy_pg.on('response', lambda r, ctx=legacy_ctx: asyncio.ensure_future(
                        self._handle_response(r, ctx)))
                    await legacy_pg.goto(url, wait_until='domcontentloaded', timeout=12000)
                    try:
                        await legacy_pg.wait_for_load_state('networkidle', timeout=self.networkidle_short_ms)
                    except Exception:
                        pass
                    await legacy_pg.close()
                    await legacy_ctx.close()
                    print("  [Legacy UA] IE11 UA 重放完成")
                except Exception as e:
                    print(f"  [Legacy UA] 跳过: {e}")
            elif not self.enable_legacy_ua:
                print("  [Legacy UA] 已禁用")

            # 触发 not-found chunk（Next.js App Router）
            if self.enable_404_probe:
                print("[3c] 触发 not-found chunk...")
                try:
                    nf_page = await context.new_page()
                    nf_page.on('response', lambda r, ctx=context: asyncio.ensure_future(
                        self._handle_response(r, ctx)))
                    await nf_page.goto(base_origin + '/__scraper_404_probe_nonexistent_path__',
                                       wait_until='domcontentloaded', timeout=8000)
                    try:
                        await nf_page.wait_for_load_state('networkidle', timeout=1500)
                    except Exception:
                        pass
                    await nf_page.close()
                    print("  [404探测] 完成")
                except Exception as e:
                    print(f"  [404探测] 跳过: {e}")
            else:
                print("[3c] 404探测已禁用")

            # Service Worker 等待
            sw_likely = any(
                '/service-worker' in r.get('url', '') or '/sw.' in r.get('url', '')
                for r in self.resources
            )
            if self.enable_service_worker_probe and sw_likely:
                print("[4] 检测到 Service Worker，等待注册...")
                try:
                    probe_page = await context.new_page()
                    probe_page.on('response', lambda r, ctx=context: asyncio.ensure_future(
                        self._handle_response(r, ctx)))
                    await probe_page.goto(url, wait_until='domcontentloaded', timeout=15000)
                    await asyncio.sleep(self.sw_wait_seconds)
                    await probe_page.reload(wait_until='domcontentloaded', timeout=12000)
                    try:
                        await probe_page.wait_for_load_state('networkidle', timeout=self.networkidle_short_ms)
                    except Exception:
                        pass
                    await probe_page.close()
                except Exception as e:
                    print(f"  警告: {e}")
            else:
                print("[4] 未检测到 Service Worker，跳过")

            # 截图
            if self.enable_screenshot:
                print("[5] 截图...")
                try:
                    shot_page = await context.new_page()
                    await shot_page.goto(url, wait_until='domcontentloaded', timeout=10000)
                    await shot_page.screenshot(path=self.output_dir / 'screenshot.png',
                                               full_page=True, timeout=8000)
                    await shot_page.close()
                except Exception as e:
                    print(f"  截图失败: {e}")
            else:
                print("[5] 截图已禁用")

            await context.close()
            await browser.close()

        self._save_manifest(url)

    # ────────────────────────────────────────────────────────────────────────
    # 结果保存
    # ────────────────────────────────────────────────────────────────────────

    def _save_manifest(self, url: str):
        stats: dict = {
            'total_resources'     : len(self.resources),
            'successful_downloads': sum(1 for r in self.resources if 'saved_path' in r),
            'soft_404_count'      : sum(1 for r in self.resources if r.get('is_soft_404')),
            'total_size_bytes'    : sum(r.get('size_bytes', 0) for r in self.resources),
            'by_type'             : {},
            'by_status'           : {},
            'by_method'           : {},
            'special_findings'    : len(self.special_findings),
        }
        for r in self.resources:
            for key, field in [
                ('by_type', 'resource_type'),
                ('by_status', 'status'),
                ('by_method', 'method'),
            ]:
                v = str(r.get(field, '?'))
                stats[key][v] = stats[key].get(v, 0) + 1

        manifest = {
            'original_url'    : url,
            'scraped_at'      : datetime.now().isoformat(),
            'statistics'      : stats,
            'special_findings': self.special_findings,
            'resources'       : self.resources,
        }
        out = self.output_dir / 'resource_manifest.json'
        out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')

        print(f"\n  总资源: {stats['total_resources']} | "
              f"成功: {stats['successful_downloads']} | "
              f"Soft 404: {stats['soft_404_count']} | "
              f"大小: {stats['total_size_bytes']/1024/1024:.1f} MB")
        print(f"  特殊发现: {stats['special_findings']}")
        print(f"  清单: {out}\n")


# ────────────────────────────────────────────────────────────────────────────
# CLI 入口
# ────────────────────────────────────────────────────────────────────────────

async def main():
    url = input("目标 URL: ").strip()
    if not url.startswith('http'):
        url = 'http://' + url
    out = input("输出目录 (默认 scraped_resources): ").strip() or "scraped_resources"
    s = ResourceScraper(output_dir=out)
    await s.scrape(url)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n用户中断")