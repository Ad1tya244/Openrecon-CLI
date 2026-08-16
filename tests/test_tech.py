import unittest
import tempfile
import io
import os
from unittest.mock import patch, AsyncMock
from rich.console import Console
from openrecon.modules.tech_fingerprint import (
    DEFAULT_FINGERPRINTS_PATH,
    load_fingerprints,
    extract_meta_tags,
    extract_asset_urls,
    collect_probe_paths,
    evaluate_active_probes,
    _resolve_relationships,
    identify_technologies,
    get_tech_fingerprint
)
import openrecon.formatter as fmt

class TestExpandedTechFingerprinting(unittest.TestCase):
    def test_single_authoritative_database_location(self):
        self.assertTrue(os.path.isfile(DEFAULT_FINGERPRINTS_PATH))
        self.assertTrue(DEFAULT_FINGERPRINTS_PATH.endswith(os.path.join("openrecon", "data", "technologies.json")))
        
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.assertFalse(os.path.exists(os.path.join(root_dir, "fingerprints")), "Duplicate root fingerprints/ must not exist")
        self.assertFalse(os.path.exists(os.path.join(root_dir, "openrecon", "fingerprints")), "Duplicate openrecon/fingerprints/ must not exist")

    def test_default_database_scale_and_variety(self):
        fingerprints = load_fingerprints()
        self.assertIsInstance(fingerprints, dict)
        self.assertGreaterEqual(len(fingerprints), 400, "Database should contain 400+ technologies")
        
        expected_techs = [
            "nginx", "Apache", "WordPress", "React", "Next.js",
            "Node.js", "Laravel", "Django", "Cloudflare", "Vue.js",
            "Angular", "Bootstrap", "Tailwind CSS", "PHP", "Express",
            "Drupal", "Joomla", "Shopify", "Google Analytics", "Google Tag Manager",
            "IIS", "Nuxt", "Rails", "Spring", "ASP.NET", "Vercel", "Netlify", "Stripe",
            "Magento", "Fastify", "Sentry", "Intercom", "Algolia", "Astro", "Docusaurus",
            "Swiper", "Bulma", "Razorpay", "PostHog", "Clerk", "Auth0",
            "Moodle", "Canvas LMS", "MediaWiki", "AdonisJS", "Umami", "Snipcart", "NextAuth.js",
            "HAProxy", "Squid", "Remix", "Blazor", "MkDocs", "VuePress", "VitePress", "OneTrust"
        ]
        for tech in expected_techs:
            self.assertIn(tech, fingerprints, f"Missing expected technology: {tech}")

    def test_phase3_newly_added_technologies(self):
        # 1. Squid via header with version
        res_squid = identify_technologies({"Via": "1.1 proxy.local (squid/5.7)"}, "")
        names_squid = [t["name"] for t in res_squid["technologies"]]
        self.assertIn("Squid", names_squid)
        squid = next(t for t in res_squid["technologies"] if t["name"] == "Squid")
        self.assertEqual(squid["version"], "5.7")

        # 2. Blazor script -> implies .NET, ASP.NET Core
        res_blazor = identify_technologies({}, '<script src="_framework/blazor.webassembly.js"></script>')
        names_blazor = [t["name"] for t in res_blazor["technologies"]]
        self.assertIn("Blazor", names_blazor)
        self.assertIn(".NET", names_blazor)
        self.assertIn("ASP.NET Core", names_blazor)

        # 3. MkDocs generator meta with version
        res_mkdocs = identify_technologies({}, '<meta name="generator" content="mkdocs-1.5.3, mkdocs-material-9.5.3" />')
        names_mkdocs = [t["name"] for t in res_mkdocs["technologies"]]
        self.assertIn("MkDocs", names_mkdocs)
        self.assertIn("Python", names_mkdocs)
        mk = next(t for t in res_mkdocs["technologies"] if t["name"] == "MkDocs")
        self.assertEqual(mk["version"], "1.5.3")

        # 4. Remix window.__remixContext -> implies React, Node.js
        res_remix = identify_technologies({}, '<script>window.__remixContext = {};</script>')
        names_remix = [t["name"] for t in res_remix["technologies"]]
        self.assertIn("Remix", names_remix)
        self.assertIn("React", names_remix)
        self.assertIn("Node.js", names_remix)

        # 5. OneTrust cookie consent script
        res_ot = identify_technologies({}, '<script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js" data-document-language="true"></script>')
        self.assertIn("OneTrust", [t["name"] for t in res_ot["technologies"]])

    def test_newly_added_technology_detections(self):
        # 1. Fastify header -> implies Node.js
        res_fastify = identify_technologies({"X-Powered-By": "Fastify"}, "")
        tech_names = [t["name"] for t in res_fastify["technologies"]]
        self.assertIn("Fastify", tech_names)
        self.assertIn("Node.js", tech_names)

        # 2. Astro meta tag
        res_astro = identify_technologies({}, '<meta name="generator" content="Astro v4.0.0" />')
        tech_names_astro = [t["name"] for t in res_astro["technologies"]]
        self.assertIn("Astro", tech_names_astro)
        astro = next(t for t in res_astro["technologies"] if t["name"] == "Astro")
        self.assertEqual(astro["version"], "4.0.0")

        # 3. Sentry script bundle
        res_sentry = identify_technologies({}, '<script src="https://browser.sentry-cdn.com/7.80.0/bundle.min.js"></script>')
        self.assertIn("Sentry", [t["name"] for t in res_sentry["technologies"]])
        sentry = next(t for t in res_sentry["technologies"] if t["name"] == "Sentry")
        self.assertEqual(sentry["version"], "7.80.0")

        # 4. Intercom widget
        res_intercom = identify_technologies({}, '<script src="https://widget.intercom.io/widget/app123"></script>')
        self.assertIn("Intercom", [t["name"] for t in res_intercom["technologies"]])

    def test_lms_wiki_and_auth_detections(self):
        # 1. Moodle session cookie
        res_moodle = identify_technologies({"Set-Cookie": "MoodleSession=abc123xyz"}, "")
        names_moodle = [t["name"] for t in res_moodle["technologies"]]
        self.assertIn("Moodle", names_moodle)
        self.assertIn("PHP", names_moodle)  # Implied

        # 2. MediaWiki meta tag with version
        res_mw = identify_technologies({}, '<meta name="generator" content="MediaWiki 1.41.0" />')
        names_mw = [t["name"] for t in res_mw["technologies"]]
        self.assertIn("MediaWiki", names_mw)
        self.assertIn("PHP", names_mw)
        mw = next(t for t in res_mw["technologies"] if t["name"] == "MediaWiki")
        self.assertEqual(mw["version"], "1.41.0")

        # 3. NextAuth.js session cookie -> implies Next.js -> React + Node.js
        res_auth = identify_technologies({"Set-Cookie": "next-auth.session-token=jwt123"}, "")
        names_auth = [t["name"] for t in res_auth["technologies"]]
        self.assertIn("NextAuth.js", names_auth)
        self.assertIn("Next.js", names_auth)
        self.assertIn("React", names_auth)
        self.assertIn("Node.js", names_auth)

        # 4. Umami analytics script
        res_umami = identify_technologies({}, '<script src="https://analytics.example.com/umami.js" data-website-id="123"></script>')
        self.assertIn("Umami", [t["name"] for t in res_umami["technologies"]])

    def test_collect_probe_paths_and_deduplication(self):
        fps = {
            "Tech1": {"paths": ["/api/v1/", "/status"]},
            "Tech2": {"probes": [{"path": "/api/v1/"}, {"path": "/health"}]},
            "Tech3": {"paths": ["api/v1", "/status/"]}
        }
        paths = collect_probe_paths(fps)
        self.assertEqual(sorted(paths), sorted(["/api/v1", "/api/v1/", "/health", "/status", "/status/"]))

    def test_evaluate_active_probes_matching(self):
        fps = {
            "WordPress": {
                "category": "CMS",
                "probes": [
                    {
                        "path": "/wp-json/",
                        "status": 200,
                        "html": [r"wp/v2"],
                        "headers": {"content-type": r"application/json"}
                    }
                ],
                "implies": ["PHP"]
            },
            "HiddenCMS": {
                "category": "CMS",
                "probes": [
                    {
                        "path": "/secret-check",
                        "status": 200,
                        "negative_html": [r"404 Not Found", r"Access Denied"],
                        "html": [r"admin-panel-marker"]
                    }
                ]
            }
        }
        probe_resps = {
            "/wp-json/": {
                "status_code": 200,
                "headers": {"content-type": "application/json; charset=UTF-8"},
                "content_text": "{\"name\":\"My Blog\",\"namespaces\":[\"wp/v2\"]}"
            },
            "/secret-check": {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "content_text": "<html><body>admin-panel-marker</body></html>"
            }
        }
        detected = evaluate_active_probes(probe_resps, fps)
        self.assertIn("WordPress", detected)
        self.assertIn("HiddenCMS", detected)

    def test_probe_status_and_negative_matching(self):
        fps = {
            "TestTech": {
                "category": "Backend",
                "probes": [
                    {
                        "path": "/status",
                        "status": [200, 204],
                        "negative_html": [r"error", r"forbidden"],
                        "html": [r"ok"]
                    }
                ]
            }
        }
        # Case 1: Negative signature present -> rejected
        resps_fail = {
            "/status": {"status_code": 200, "content_text": "403 Forbidden error"}
        }
        det_fail = evaluate_active_probes(resps_fail, fps)
        self.assertNotIn("TestTech", det_fail)

        # Case 2: Status mismatch -> rejected
        resps_status_fail = {
            "/status": {"status_code": 500, "content_text": "ok"}
        }
        det_status_fail = evaluate_active_probes(resps_status_fail, fps)
        self.assertNotIn("TestTech", det_status_fail)

        # Case 3: Match
        resps_pass = {
            "/status": {"status_code": 204, "content_text": "ok"}
        }
        det_pass = evaluate_active_probes(resps_pass, fps)
        self.assertIn("TestTech", det_pass)

    def test_wildcard_spa_probe_protection(self):
        root_html = "<html><head><title>My SPA Homepage</title></head><body><h1>Welcome</h1></body></html>"
        fps = {
            "Magento": {
                "category": "CMS",
                "probes": [
                    {
                        "path": "/static/frontend/Magento/",
                        "status": 200,
                        "html": ["Magento"]
                    }
                ]
            }
        }
        # When SPA router returns the homepage on probe request
        probe_resps = {
            "/static/frontend/Magento/": {
                "status_code": 200,
                "content_text": root_html
            }
        }
        det = evaluate_active_probes(probe_resps, fps, root_html=root_html)
        self.assertNotIn("Magento", det)

    def test_generic_active_200_probe_rejected(self):
        fps = {
            "GenericTech": {
                "category": "CMS",
                "probes": [
                    {
                        "path": "/some-generic-path",
                        "status": 200
                    }
                ]
            }
        }
        probe_resps = {
            "/some-generic-path": {
                "status_code": 200,
                "content_text": "<html>Generic content</html>"
            }
        }
        det = evaluate_active_probes(probe_resps, fps)
        self.assertNotIn("GenericTech", det)

    def test_magento_false_positive_rejected_on_generic_words(self):
        html = """
        <html>
        <head><title>General Store</title></head>
        <body>
            <div class="product-catalog">
                <a href="/store/products">View Catalog</a>
                <img src="/static/images/logo.png">
            </div>
        </body>
        </html>
        """
        headers = {"Server": "Apache/2.4.58 (Ubuntu)"}
        res = identify_technologies(headers, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertNotIn("Magento", tech_names)
        self.assertIn("Apache", tech_names)

    def test_genuine_magento_detected(self):
        html = """
        <html>
        <head>
            <script src="/static/frontend/Magento/luma/en_US/mage/cookies.js"></script>
        </head>
        <body data-container="body" data-mage-init='{"loader": {}}'>
            <div class="page-wrapper"></div>
        </body>
        </html>
        """
        headers = {"Set-Cookie": "frontend=a1b2c3d4e5f6a1b2c3d4e5f6a1; path=/"}
        res = identify_technologies(headers, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("Magento", tech_names)
        self.assertIn("PHP", tech_names)

    def test_genuine_magento_probe_detected(self):
        fps = load_fingerprints()
        probe_resps = {
            "/static/frontend/Magento/": {
                "status_code": 200,
                "content_text": "/* Magento Luma Theme Assets */\nvar Magento_Ui = {};"
            }
        }
        det = evaluate_active_probes(probe_resps, fps)
        self.assertIn("Magento", det)

    def test_genuine_drupal_detected_with_version(self):
        html = """
        <html>
        <head>
            <meta name="Generator" content="Drupal 10.3.6 (https://www.drupal.org)" />
            <script src="/core/misc/drupal.js"></script>
        </head>
        <body class="path-frontpage drupal-theme">
            <div data-drupal-selector="edit-search"></div>
            <script>drupalSettings = { "path": { "isFront": true } };</script>
        </body>
        </html>
        """
        headers = {
            "X-Generator": "Drupal 10.3.6 (https://www.drupal.org)",
            "X-Drupal-Cache": "HIT"
        }
        res = identify_technologies(headers, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("Drupal", tech_names)
        self.assertIn("PHP", tech_names)
        
        drupal_tech = next(t for t in res["technologies"] if t["name"] == "Drupal")
        self.assertEqual(drupal_tech["version"], "10.3.6")

    def test_php_detection_with_version_and_without_version(self):
        # 1. With exposed version in X-Powered-By
        res1 = identify_technologies({"X-Powered-By": "PHP/8.3.6"}, "")
        tech_names1 = [t["name"] for t in res1["technologies"]]
        self.assertIn("PHP", tech_names1)
        php1 = next(t for t in res1["technologies"] if t["name"] == "PHP")
        self.assertEqual(php1["version"], "8.3.6")

        # 2. Without version (e.g. PHPSESSID cookie or .php link)
        res2 = identify_technologies({"Set-Cookie": "PHPSESSID=abc123xyz"}, "<a href='contact.php'>Contact</a>")
        tech_names2 = [t["name"] for t in res2["technologies"]]
        self.assertIn("PHP", tech_names2)
        php2 = next(t for t in res2["technologies"] if t["name"] == "PHP")
        self.assertIsNone(php2["version"])

    def test_jquery_version_extraction_from_script_src(self):
        html = '<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>'
        res = identify_technologies({}, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("jQuery", tech_names)
        jq = next(t for t in res["technologies"] if t["name"] == "jQuery")
        self.assertEqual(jq["version"], "3.7.1")

    def test_bootstrap_detection_from_css_and_js(self):
        html = """
        <link rel="stylesheet" href="/css/bootstrap.min.css">
        <script src="/js/bootstrap.bundle.min.js"></script>
        """
        res = identify_technologies({}, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("Bootstrap", tech_names)

    def test_nextjs_asset_paths_detection(self):
        html = """
        <html>
        <head>
            <script src="/_next/static/chunks/main.js"></script>
        </head>
        <body>
            <div id="__next"></div>
        </body>
        </html>
        """
        res = identify_technologies({}, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("Next.js", tech_names)
        self.assertIn("React", tech_names)
        self.assertIn("Node.js", tech_names)

    def test_react_vue_angular_passive_detection(self):
        res_react = identify_technologies({}, '<div data-reactroot="">Content</div>')
        self.assertIn("React", [t["name"] for t in res_react["technologies"]])

        res_vue = identify_technologies({}, '<div id="app" data-v-1234abcd="">Content</div>')
        self.assertIn("Vue.js", [t["name"] for t in res_vue["technologies"]])

        res_ng = identify_technologies({}, '<div ng-version="17.2.0">Content</div>')
        self.assertIn("Angular", [t["name"] for t in res_ng["technologies"]])
        ng_tech = next(t for t in res_ng["technologies"] if t["name"] == "Angular")
        self.assertEqual(ng_tech["version"], "17.2.0")

    def test_normal_script_asset_fingerprints_work_without_probes(self):
        html = """
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwind.min.css">
        <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
        """
        res = identify_technologies({}, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("Tailwind CSS", tech_names)
        self.assertIn("Axios", tech_names)
        self.assertIn("Lodash", tech_names)

    def test_circular_relationship_protection(self):
        fps = {
            "A": {"category": "CatA", "implies": ["B"]},
            "B": {"category": "CatB", "implies": ["C"]},
            "C": {"category": "CatC", "implies": ["A"]}
        }
        det = {"A": {"name": "A", "version": None, "category": "CatA"}}
        res = _resolve_relationships(det, fps)
        self.assertIn("A", res)
        self.assertIn("B", res)
        self.assertIn("C", res)

    def test_header_detection_and_version_extraction(self):
        headers = {
            "Server": "nginx/1.24.0 (Ubuntu)",
            "X-Powered-By": "PHP/8.2.10"
        }
        res = identify_technologies(headers, "")
        tech_names = [t["name"] for t in res["technologies"]]
        
        self.assertIn("nginx", tech_names)
        nginx_tech = next(t for t in res["technologies"] if t["name"] == "nginx")
        self.assertEqual(nginx_tech["version"], "1.24.0")
        self.assertEqual(nginx_tech["category"], "Web Server")

        self.assertIn("PHP", tech_names)
        php_tech = next(t for t in res["technologies"] if t["name"] == "PHP")
        self.assertEqual(php_tech["version"], "8.2.10")
        self.assertEqual(php_tech["category"], "Backend")

    def test_cookie_detection(self):
        headers = {
            "Set-Cookie": "laravel_session=eyJpdiI6...; Path=/; HttpOnly"
        }
        res = identify_technologies(headers, "")
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("Laravel", tech_names)
        self.assertIn("PHP", tech_names)
        laravel_tech = next(t for t in res["technologies"] if t["name"] == "Laravel")
        self.assertEqual(laravel_tech["category"], "Backend")

    def test_html_and_dom_detection(self):
        html = """
        <html>
        <head></head>
        <body>
            <div data-reactroot="">Hello React</div>
            <input type="hidden" name="csrfmiddlewaretoken" value="abc123xyz" />
        </body>
        </html>
        """
        res = identify_technologies({}, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("React", tech_names)
        self.assertIn("Django", tech_names)
        self.assertIn("Python", tech_names)

    def test_meta_tag_extraction_and_version(self):
        html = """
        <html>
        <head>
            <meta name="generator" content="WordPress 6.4.2" />
        </head>
        </html>
        """
        res = identify_technologies({}, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("WordPress", tech_names)
        wp_tech = next(t for t in res["technologies"] if t["name"] == "WordPress")
        self.assertEqual(wp_tech["version"], "6.4.2")
        self.assertEqual(wp_tech["category"], "CMS")
        self.assertIn("PHP", tech_names)

    def test_script_src_urls_detection(self):
        html = """
        <html>
        <head>
            <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
            <script src="/_next/static/chunks/main.js"></script>
        </head>
        </html>
        """
        res = identify_technologies({}, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("jQuery", tech_names)
        jq = next(t for t in res["technologies"] if t["name"] == "jQuery")
        self.assertEqual(jq["version"], "3.7.1")
        self.assertIn("Next.js", tech_names)
        self.assertIn("React", tech_names)
        self.assertIn("Node.js", tech_names)

    def test_css_asset_urls_detection(self):
        html = """
        <html>
        <head>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
            <link rel="stylesheet" href="/assets/css/tailwind.min.css">
        </head>
        </html>
        """
        res = identify_technologies({}, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("Bootstrap", tech_names)
        self.assertIn("Tailwind CSS", tech_names)

    def test_javascript_inline_property_detection(self):
        html = """
        <html>
        <head>
            <script>
                window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = {};
                var Drupal = Drupal || {};
                Drupal.settings = { "basePath": "/" };
            </script>
        </head>
        </html>
        """
        res = identify_technologies({}, html)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("React", tech_names)
        self.assertIn("Drupal", tech_names)

    def test_robots_txt_detection(self):
        robots = "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n"
        res = identify_technologies({}, "", robots_txt=robots)
        tech_names = [t["name"] for t in res["technologies"]]
        self.assertIn("WordPress", tech_names)
        self.assertIn("PHP", tech_names)

    def test_url_and_hostname_detection(self):
        custom_fps = {
            "ShopifyPlatform": {
                "category": "CMS",
                "url": [r"myshopify\.com"]
            }
        }
        res = identify_technologies({}, "", fingerprints=custom_fps, url="https://store.myshopify.com")
        self.assertIn("ShopifyPlatform", [t["name"] for t in res["technologies"]])

    def test_multiple_signals_deduplication(self):
        headers = {
            "X-Generator": "WordPress 6.4.2",
            "Set-Cookie": "wordpress_test_cookie=WP+Cookie; path=/"
        }
        html = """
        <html>
        <head>
            <meta name="generator" content="WordPress 6.4.2" />
            <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
            <script src="/wp-includes/js/wp-emoji.js"></script>
        </head>
        </html>
        """
        res = identify_technologies(headers, html)
        wp_entries = [t for t in res["technologies"] if t["name"] == "WordPress"]
        
        self.assertEqual(len(wp_entries), 1)
        self.assertEqual(wp_entries[0]["version"], "6.4.2")
        self.assertEqual(wp_entries[0]["category"], "CMS")

    def test_unknown_version_when_not_exposed(self):
        headers = {"Server": "cloudflare"}
        res = identify_technologies(headers, "")
        cf_tech = next(t for t in res["technologies"] if t["name"] == "Cloudflare")
        self.assertIsNone(cf_tech["version"])
        self.assertEqual(cf_tech["category"], "CDN")

    def test_empty_results_and_false_positives(self):
        headers = {"Content-Type": "text/html", "Cache-Control": "max-age=3600"}
        html = "<html><body><p>generic reactive and angular text</p></body></html>"
        res = identify_technologies(headers, html)
        self.assertEqual(res["total"], 0)
        self.assertEqual(res["technologies"], [])
        self.assertEqual(res["categories"], {})

    def test_custom_fingerprint_loading(self):
        custom_data = """{
            "technologies": {
                "CustomTech": {
                    "category": "CustomCategory",
                    "headers": {"X-Custom": "CustomTech/([0-9.]+)"}
                }
            }
        }"""
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write(custom_data)
            f_path = f.name

        try:
            fps = load_fingerprints(f_path)
            self.assertIn("CustomTech", fps)
            self.assertEqual(fps["CustomTech"]["category"], "CustomCategory")
        finally:
            os.unlink(f_path)

    def test_render_tech_combined_key_value_and_omission(self):
        data = {
            "categories": {
                "Web Server": [{"name": "Apache", "version": "2.4.58"}],
                "Frontend": [{"name": "Bootstrap", "version": None}, {"name": "jQuery", "version": None}],
                "Backend": [{"name": "Node.js", "version": None}, {"name": "Express", "version": None}],
                "CMS": [{"name": "WordPress", "version": None}],
                "CDN": [{"name": "Cloudflare", "version": None}]
            }
        }
        buf = io.StringIO()
        test_console = Console(file=buf, force_terminal=False, no_color=True, highlight=False)
        
        orig_console = fmt.console
        fmt.console = test_console
        try:
            fmt.render_tech(data)
        finally:
            fmt.console = orig_console

        output = buf.getvalue()
        self.assertIn("Web Server       Apache 2.4.58", output)
        self.assertIn("Frontend         Bootstrap, jQuery", output)
        self.assertIn("Backend          Node.js, Express", output)
        self.assertIn("CMS              WordPress", output)
        self.assertIn("CDN              Cloudflare", output)

        self.assertEqual(output.count("Web Server"), 1)
        self.assertEqual(output.count("Frontend"), 1)
        self.assertEqual(output.count("Backend"), 1)
        self.assertEqual(output.count("CMS"), 1)
        self.assertEqual(output.count("CDN"), 1)

    def test_render_tech_long_value_wrapping_and_alignment(self):
        data = {
            "categories": {
                "Frontend": [
                    {"name": "React", "version": None},
                    {"name": "Next.js", "version": None},
                    {"name": "Bootstrap", "version": None},
                    {"name": "jQuery", "version": None},
                    {"name": "Vue.js", "version": None},
                    {"name": "Angular", "version": None},
                    {"name": "Axios", "version": None},
                    {"name": "Lodash", "version": None}
                ]
            }
        }
        buf = io.StringIO()
        test_console = Console(file=buf, force_terminal=False, no_color=True, highlight=False)
        
        orig_console = fmt.console
        fmt.console = test_console
        try:
            fmt.render_tech(data)
        finally:
            fmt.console = orig_console

        output = buf.getvalue()
        lines = [line for line in output.splitlines() if line.strip()]
        self.assertTrue(any("Frontend         React, Next.js" in l for l in lines))
        continuation_lines = [l for l in lines if "Lodash" in l]
        self.assertTrue(len(continuation_lines) >= 1)
        self.assertTrue(continuation_lines[0].startswith(" " * 21))

    def test_render_tech_empty_output(self):
        buf = io.StringIO()
        test_console = Console(file=buf, force_terminal=False, no_color=True, highlight=False)
        
        orig_console = fmt.console
        fmt.console = test_console
        try:
            fmt.render_tech({})
        finally:
            fmt.console = orig_console

        self.assertIn("No technologies identified.", buf.getvalue())

class TestTechScannerAsync(unittest.IsolatedAsyncioTestCase):
    async def test_get_tech_fingerprint_combined_passive_and_active(self):
        mock_responses = {
            "https://target.local": {
                "status_code": 200,
                "headers": {"server": "Apache/2.4.58 (Ubuntu)"},
                "content_text": "<html><head><script src='/_next/static/main.js'></script></head><body></body></html>"
            },
            "https://target.local/robots.txt": {
                "status_code": 404,
                "content_text": ""
            },
            "https://target.local/wp-json/": {
                "status_code": 200,
                "headers": {"content-type": "application/json"},
                "content_text": "{\"name\":\"My Blog\",\"namespaces\":[\"wp/v2\"]}"
            }
        }

        async def mock_safe_get(url, headers=None):
            return mock_responses.get(url, {"status_code": 404, "content_text": ""})

        with patch("openrecon.modules.tech_fingerprint.safe_get", side_effect=mock_safe_get):
            res = await get_tech_fingerprint("target.local")

        tech_names = [t["name"] for t in res["technologies"]]
        # From passive response
        self.assertIn("Apache", tech_names)
        self.assertIn("Next.js", tech_names)
        self.assertIn("React", tech_names)
        self.assertIn("Node.js", tech_names)
        # From active probe /wp-json/
        self.assertIn("WordPress", tech_names)
        self.assertIn("PHP", tech_names)  # Implied by WordPress

if __name__ == "__main__":
    unittest.main()
