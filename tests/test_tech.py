import unittest
from openrecon.modules.tech_fingerprint import (
    identify_technologies,
    extract_meta_tags,
    extract_asset_urls,
    standardize_category
)
from openrecon.formatter import render_tech

class TestTechFingerprintEvidenceBased(unittest.TestCase):
    def test_header_evidence_matching(self):
        headers = {
            "server": "nginx/1.18.0",
            "x-powered-by": "PHP/8.1.2"
        }
        res = identify_technologies(headers=headers, html="")
        tech_names = [t["name"].lower() for t in res["technologies"]]
        
        self.assertIn("nginx", tech_names)
        self.assertIn("php", tech_names)

        nginx_tech = next(t for t in res["technologies"] if t["name"].lower() == "nginx")
        self.assertEqual(nginx_tech["version"], "1.18.0")
        self.assertEqual(nginx_tech["category"], "Web Server")

        php_tech = next(t for t in res["technologies"] if t["name"].lower() == "php")
        self.assertEqual(php_tech["version"], "8.1.2")
        self.assertEqual(php_tech["category"], "Backend")

    def test_meta_and_script_evidence_matching(self):
        html = """
        <html>
        <head>
            <meta name="generator" content="WordPress 6.2.2" />
            <script src="/wp-content/themes/theme/main.js"></script>
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        </head>
        <body>
        </body>
        </html>
        """
        res = identify_technologies(headers={}, html=html)
        tech_names = [t["name"].lower() for t in res["technologies"]]
        
        self.assertIn("wordpress", tech_names)
        self.assertIn("jquery", tech_names)

        wp_tech = next(t for t in res["technologies"] if t["name"].lower() == "wordpress")
        self.assertEqual(wp_tech["version"], "6.2.2")
        self.assertEqual(wp_tech["category"], "CMS")

    def test_category_standardization(self):
        self.assertEqual(standardize_category("web servers"), "Web Server")
        self.assertEqual(standardize_category("programming languages"), "Backend")
        self.assertEqual(standardize_category("ui frameworks"), "Frontend")
        self.assertEqual(standardize_category("cms"), "CMS")
        self.assertEqual(standardize_category("web frameworks"), "Framework")
        self.assertEqual(standardize_category("paas"), "Runtime")
        self.assertEqual(standardize_category("analytics"), "Analytics")
        self.assertEqual(standardize_category("javascript libraries"), "JavaScript Libraries")
        self.assertEqual(standardize_category("cdn"), "CDN / Proxy")

    def test_render_tech_output(self):
        data = {
            "categories": {
                "Web Server": [{"name": "Nginx", "version": "1.18.0"}],
                "Backend": [{"name": "PHP", "version": "8.1"}],
                "CMS": [{"name": "WordPress", "version": "6.2"}],
                "JavaScript Libraries": [{"name": "jQuery", "version": "3.6.0"}]
            }
        }
        render_tech(data)

    def test_nextjs_and_react_version_matching(self):
        next_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="/_next/static/css/tailwind.css">
            <script src="/_next/static/chunks/main-app.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>
        </head>
        <body>
            <div id="__next">
                <div class="min-h-screen bg-gray-900">Next.js App</div>
            </div>
            <script>window.__NEXT_DATA__ = { page: "/", buildId: "12345" };</script>
        </body>
        </html>
        """
        res = identify_technologies(
            headers={"Server": "Vercel", "X-Powered-By": "Next.js"},
            html=next_html
        )
        tech_map = {t["name"].lower(): t for t in res["technologies"]}
        
        self.assertIn("next.js", tech_map)
        self.assertIn("react", tech_map)
        self.assertEqual(tech_map["react"]["version"], "18.2.0")
        self.assertIn("tailwind css", tech_map)
        # Verify false positive prevention
        self.assertNotIn("google analytics", tech_map)

    def test_wordpress_jquery_and_bootstrap_matching(self):
        wp_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="generator" content="WordPress 6.4.2">
            <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
            <link rel="stylesheet" href="/assets/bootstrap-5.3.2.min.css">
            <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
            <script src="https://code.jquery.com/jquery-migrate-1.2.1.min.js"></script>
        </head>
        <body class="wp-custom-logo">
            <div class="wp-content">WordPress Content</div>
        </body>
        </html>
        """
        res = identify_technologies(
            headers={"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.14"},
            html=wp_html
        )
        tech_map = {t["name"].lower(): t for t in res["technologies"]}
        
        self.assertIn("wordpress", tech_map)
        self.assertEqual(tech_map["wordpress"]["version"], "6.4.2")
        self.assertIn("bootstrap", tech_map)
        self.assertEqual(tech_map["bootstrap"]["version"], "5.3.2")
        self.assertIn("jquery", tech_map)
        self.assertEqual(tech_map["jquery"]["version"], "3.7.1")
        self.assertIn("jquery migrate", tech_map)
        self.assertEqual(tech_map["jquery migrate"]["version"], "1.2.1")

    def test_benchmark_wordpress(self):
        wp = identify_technologies(
            headers={"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.14"},
            html='<meta name="generator" content="WordPress 6.4.2"><link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">'
        )
        tech_map = {t["name"].lower(): t for t in wp["technologies"]}
        self.assertIn("wordpress", tech_map)
        self.assertEqual(tech_map["wordpress"]["version"], "6.4.2")
        self.assertIn("nginx", tech_map)
        self.assertEqual(tech_map["nginx"]["version"], "1.24.0")
        self.assertIn("php", tech_map)
        self.assertEqual(tech_map["php"]["version"], "8.2.14")

    def test_benchmark_nextjs_and_react(self):
        nextjs = identify_technologies(
            headers={"Server": "Vercel", "X-Powered-By": "Next.js"},
            html='<div id="__next"></div><script src="/_next/static/chunks/main-app.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>'
        )
        tech_map = {t["name"].lower(): t for t in nextjs["technologies"]}
        self.assertIn("next.js", tech_map)
        self.assertIn("react", tech_map)
        self.assertEqual(tech_map["react"]["version"], "18.2.0")
        self.assertIn("vercel", tech_map)

    def test_benchmark_nuxt_and_vue(self):
        nuxt = identify_technologies(
            headers={"Server": "cloudflare"},
            html='<div id="__nuxt" data-v-1234abcd></div><script src="/_nuxt/app.js"></script><script src="https://unpkg.com/vue@3.3.4/dist/vue.global.prod.js"></script>'
        )
        tech_map = {t["name"].lower(): t for t in nuxt["technologies"]}
        self.assertIn("nuxt", tech_map)
        self.assertIn("vue.js", tech_map)
        self.assertEqual(tech_map["vue.js"]["version"], "3.3.4")
        self.assertIn("cloudflare", tech_map)

    def test_benchmark_angular(self):
        angular = identify_technologies(
            headers={},
            html='<app-root ng-version="17.0.5"></app-root><script src="/main.1234abcd.js"></script>'
        )
        tech_map = {t["name"].lower(): t for t in angular["technologies"]}
        self.assertIn("angular", tech_map)
        self.assertEqual(tech_map["angular"]["version"], "17.0.5")

    def test_benchmark_laravel(self):
        laravel = identify_technologies(
            headers={"Set-Cookie": "laravel_session=eyJpdiI6...; expires=...; path=/; httponly"},
            html='<script>window.Laravel = { csrfToken: "xyz123" };</script>'
        )
        tech_map = {t["name"].lower(): t for t in laravel["technologies"]}
        self.assertIn("laravel", tech_map)
        # Must not falsely identify Flask
        self.assertNotIn("flask", tech_map)

    def test_benchmark_django(self):
        django = identify_technologies(
            headers={"Set-Cookie": "csrftoken=abc123xyz456; expires=...; path=/"},
            html='<form><input type="hidden" name="csrfmiddlewaretoken" value="abc123xyz456"></form>'
        )
        tech_map = {t["name"].lower(): t for t in django["technologies"]}
        self.assertIn("django", tech_map)

    def test_benchmark_bootstrap_jquery_font_awesome(self):
        fe_libs = identify_technologies(
            headers={},
            html='<link rel="stylesheet" href="/assets/bootstrap-5.3.2.min.css"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"><script src="/assets/jquery-3.7.1.min.js"></script>'
        )
        tech_map = {t["name"].lower(): t for t in fe_libs["technologies"]}
        self.assertIn("bootstrap", tech_map)
        self.assertEqual(tech_map["bootstrap"]["version"], "5.3.2")
        self.assertIn("jquery", tech_map)
        self.assertEqual(tech_map["jquery"]["version"], "3.7.1")
        self.assertIn("font awesome", tech_map)
        self.assertEqual(tech_map["font awesome"]["version"], "6.4.0")
        # Must not falsely match Vite from /assets/
        self.assertNotIn("vite", tech_map)

    def test_benchmark_google_analytics(self):
        ga = identify_technologies(
            headers={},
            html='<script src="https://www.googletagmanager.com/gtag/js?id=G-1234567890"></script><script>gtag("config", "G-1234567890");</script>'
        )
        tech_map = {t["name"].lower(): t for t in ga["technologies"]}
        self.assertIn("google analytics", tech_map)

    def test_benchmark_cloudflare_cdn(self):
        cdn_cf = identify_technologies(
            headers={"server": "cloudflare", "cf-ray": "857492a-EWR"},
            html=""
        )
        tech_map = {t["name"].lower(): t for t in cdn_cf["technologies"]}
        self.assertIn("cloudflare", tech_map)

    def test_benchmark_adversarial_false_positives(self):
        adversarial = identify_technologies(
            headers={"Server": "CustomApp/1.0"},
            html="""
            <div class="bg-gray-900 text-gray-100 p-8">
                <h1>Welcome to our agency</h1>
                <p>We love using React and Angular and Vue to build fast apps with Django and Laravel backends.</p>
                <p>Our phone number is 1-800-555-0199.</p>
                <script src="https://code.jquery.com/jquery-migrate-1.2.1.min.js"></script>
            </div>
            """
        )
        tech_map = {t["name"].lower(): t for t in adversarial["technologies"]}
        
        # Arbitrary prose must NOT trigger framework presence
        self.assertNotIn("google analytics", tech_map)
        self.assertNotIn("react", tech_map)
        self.assertNotIn("angular", tech_map)
        self.assertNotIn("vue.js", tech_map)
        self.assertNotIn("django", tech_map)
        self.assertNotIn("laravel", tech_map)
        
        # jquery-migrate must be its own tech and not pollute core jQuery version
        self.assertIn("jquery migrate", tech_map)
        self.assertEqual(tech_map["jquery migrate"]["version"], "1.2.1")
        self.assertIn("jquery", tech_map)
        self.assertIsNone(tech_map["jquery"]["version"])

    def test_engine_implies_excludes_requires(self):
        # 1. Test Implies: WordPress implies PHP & MySQL
        wp_res = identify_technologies(
            headers={},
            html='<meta name="generator" content="WordPress 6.4.2">'
        )
        tech_map = {t["name"].lower(): t for t in wp_res["technologies"]}
        self.assertIn("wordpress", tech_map)
        self.assertIn("php", tech_map)
        self.assertIn("mysql", tech_map)

        # 2. Test Excludes: Next.js excludes Create React App
        next_res = identify_technologies(
            headers={"X-Powered-By": "Next.js"},
            html='<div id="__next"></div>'
        )
        tech_map = {t["name"].lower(): t for t in next_res["technologies"]}
        self.assertIn("next.js", tech_map)
        self.assertNotIn("create react app", tech_map)



class TestIndependentUpstreamEngineIntegration(unittest.TestCase):
    def test_ast_jsluice_endpoint_discovery_and_classification(self):
        from openrecon.modules.page_intel import analyze_javascript_requests
        js_code = """
        fetch("/api/v1/users", { method: "POST" });
        axios.post("/api/v2/items");
        const config = { url: "/auth/login", method: "PUT" };
        """
        apis, _, _, _, _ = analyze_javascript_requests(js_code, "example.com")
        
        methods = {ep["method"]: ep for ep in apis}
        self.assertIn("POST", methods)
        self.assertIn("PUT", methods)
        
        # Verify classification
        post_ep = methods["POST"]
        self.assertEqual(post_ep["class"], "rest")
        
        put_ep = next(ep for ep in apis if ep["method"] == "PUT")
        self.assertEqual(put_ep["class"], "rest")

    def test_ast_html_sinks_extraction(self):
        from openrecon.modules.page_intel import DOMSourceParser
        html = """
        <html>
        <body>
            <iframe src="/embedded-frame.html"></iframe>
            <button formaction="/submit-form" formmethod="POST">Submit</button>
            <meta http-equiv="refresh" content="0;url=/redirected-path">
        </body>
        </html>
        """
        parser = DOMSourceParser("https://example.com")
        parser.feed(html)
        
        # Verify button formaction endpoint
        btn_ep = next(ep for ep in parser.dom_api_endpoints if ep["source"] == "HTML_BUTTON_FORMACTION")
        self.assertEqual(btn_ep["url"], "/submit-form")
        self.assertEqual(btn_ep["method"], "POST")
        
        # Verify meta refresh redirect and iframe src added to links
        self.assertIn("/embedded-frame.html", parser.href_links)
        self.assertIn("/redirected-path", parser.href_links)

    def test_engine_implies_and_excludes_relation_resolution(self):
        # Next.js implies React and Node.js
        res = identify_technologies(
            headers={"X-Powered-By": "Next.js"},
            html=""
        )
        tech_names = [t["name"].lower() for t in res["technologies"]]
        self.assertIn("next.js", tech_names)
        self.assertIn("react", tech_names)
        self.assertIn("node.js", tech_names)

    def test_false_positive_resistance(self):
        res = identify_technologies(
            headers={},
            html="<html><body>This is a plain webpage with no framework whatsoever.</body></html>"
        )
        tech_names = [t["name"].lower() for t in res["technologies"]]
        # Plain text should not match React or Angular
        self.assertNotIn("react", tech_names)
        self.assertNotIn("angular", tech_names)




class TestUpstreamEngineRegressionAndAccuracy(unittest.TestCase):
    def test_technology_deduplication(self):
        from openrecon.modules.tech_fingerprint import merge_and_deduplicate_detections
        detections = [
            {"name": "Apache", "version": None, "confidence": 100, "categories": [{"id": 22}]},
            {"name": "Apache HTTP Server", "version": "2.4.58", "confidence": 100, "categories": [{"id": 22}]}
        ]
        merged = merge_and_deduplicate_detections(detections)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["name"], "Apache HTTP Server")
        self.assertEqual(merged[0]["version"], "2.4.58")

    def test_category_presentation_independent_of_detection(self):
        from openrecon.modules.tech_fingerprint import map_engine_cats_to_presentation
        
        # Web Server ID
        cat = map_engine_cats_to_presentation([{"id": 22}], "Apache HTTP Server")
        self.assertEqual(cat, "Web Server")
        
        # Miscellaneous or standard overrides
        og_cat = map_engine_cats_to_presentation([{"id": 19}], "Open Graph")
        self.assertEqual(og_cat, "Web standards / metadata")

        # Categorization audit regression tests
        self.assertEqual(map_engine_cats_to_presentation([], "Ubuntu"), "Security / Infrastructure")
        self.assertEqual(map_engine_cats_to_presentation([], "EthicalAds"), "Analytics")
        self.assertEqual(map_engine_cats_to_presentation([], "OneTrust"), "Security / Infrastructure")
        self.assertEqual(map_engine_cats_to_presentation([], "Google Fonts"), "CDN / Proxy")
        self.assertEqual(map_engine_cats_to_presentation([], "Google Font API"), "CDN / Proxy")
        self.assertEqual(map_engine_cats_to_presentation([], "Google Custom Search"), "CMS")
        self.assertEqual(map_engine_cats_to_presentation([], "HTTP/3"), "Web standards / metadata")
        self.assertEqual(map_engine_cats_to_presentation([], "HSTS"), "Security / Infrastructure")
        self.assertEqual(map_engine_cats_to_presentation([], "Cloudflare Bot Management"), "Security / Infrastructure")

    def test_filtered_static_extension_validation(self):
        from openrecon.modules.page_intel import is_filtered_static_extension
        
        # Media / Static assets filtered
        self.assertTrue(is_filtered_static_extension("/images/banner.png"))
        self.assertTrue(is_filtered_static_extension("/styles/main.png?v=2"))
        self.assertTrue(is_filtered_static_extension("/downloads/manual.pdf#page=1"))
        
        # Code endpoints not filtered
        self.assertFalse(is_filtered_static_extension("/api/v1/auth.php"))
        self.assertFalse(is_filtered_static_extension("/data/feed.json"))
        self.assertFalse(is_filtered_static_extension("/portal/config.xml"))



    def test_ast_websocket_extraction(self):
        from openrecon.modules.page_intel import analyze_javascript_requests
        js_code = """
        const ws = new WebSocket("wss://api.example.com/v2/feed");
        const badWs = new WebSocket("wss://thirdparty.com/feed");
        """
        # Scan with target_domain="example.com"
        apis, _, _, _, _ = analyze_javascript_requests(js_code, "example.com")
        endpoints = [f"{ep['method']} {ep['url']}" for ep in apis]
        self.assertIn("WS wss://api.example.com/v2/feed", endpoints)
        self.assertNotIn("WS wss://thirdparty.com/feed", endpoints)

    def test_ast_sse_extraction(self):
        from openrecon.modules.page_intel import analyze_javascript_requests
        js_code = """
        const sse = new EventSource("/sse-route");
        const badSse = new EventSource("https://thirdparty.com/sse");
        """
        apis, _, _, _, _ = analyze_javascript_requests(js_code, "example.com")
        endpoints = [f"{ep['method']} {ep['url']}" for ep in apis]
        self.assertIn("SSE /sse-route", endpoints)
        self.assertNotIn("SSE https://thirdparty.com/sse", endpoints)

    def test_ast_absolute_api_literal(self):
        from openrecon.modules.page_intel import analyze_javascript_requests
        js_code = """
        const url = "https://api.example.com/v2/auth";
        const badUrl = "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js";
        """
        apis, _, _, _, _ = analyze_javascript_requests(js_code, "example.com")
        endpoints = [f"{ep['method']} {ep['url']}" for ep in apis]
        self.assertIn("GET https://api.example.com/v2/auth", endpoints)
        self.assertNotIn("GET https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js", endpoints)


if __name__ == "__main__":
    unittest.main()
