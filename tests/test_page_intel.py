import unittest
from unittest.mock import patch, AsyncMock
import io
import json
from rich.console import Console
from openrecon.modules.page_intel import (
    DOMSourceParser,
    extract_dom_technology_evidence,
    filter_functional_forms,
    extract_meaningful_app_routes,
    analyze_javascript_requests,
    extract_infrastructure_and_sensitive,
    extract_graphql_operations,
    extract_oauth_configurations,
    categorize_static_references,
    extract_source_map_references,
    detect_library_evidence,
    analyze_page_intel,
    strip_js_comments,
    extract_balanced_call,
    normalize_js_endpoint_url
)
from openrecon.modules.tech_fingerprint import merge_technology_evidence, identify_technologies
from openrecon.formatter import render_page_intel, render_tech

class TestPageSourceIntelligence(unittest.TestCase):
    def test_comment_stripping(self):
        js_code = """
        // fetch("/api/commented/endpoint", { method: "POST" });
        /*
        axios.get("/api/blocked/secret");
        */
        const active = "fetch('/api/not/commented')";
        """
        cleaned = strip_js_comments(js_code)
        self.assertNotIn("/api/commented/endpoint", cleaned)
        self.assertNotIn("/api/blocked/secret", cleaned)
        self.assertIn("fetch('/api/not/commented')", cleaned)

    def test_balanced_call_extraction(self):
        code = """
        fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });
        """
        fetch_idx = code.find("fetch")
        open_paren = code.find("(", fetch_idx)
        call_content, end_pos = extract_balanced_call(code, open_paren)
        self.assertIn("/api/login", call_content)
        self.assertIn("username", call_content)
        self.assertIn("password", call_content)

    def test_fetch_with_json_stringify_params(self):
        js_code = """
        fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: username,
                password: password,
                rememberMe: true
            })
        });
        """
        apis, routes, ws, cfgs, crefs = analyze_javascript_requests(js_code, "example.com")
        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["method"], "POST")
        self.assertEqual(apis[0]["url"], "/api/login")
        self.assertIn("username", apis[0]["params"])
        self.assertIn("password", apis[0]["params"])
        self.assertIn("rememberMe", apis[0]["params"])
        self.assertEqual(apis[0]["source"], "JS_FETCH")

    def test_sendbeacon_and_eventsource(self):
        js_code = """
        navigator.sendBeacon("/api/analytics/track", JSON.stringify({ event: "click", ts: 1700000000 }));
        const sse = new EventSource("/sse/notifications");
        """
        apis, routes, ws, cfgs, crefs = analyze_javascript_requests(js_code, "example.com")
        api_map = {a["url"]: a for a in apis}
        
        self.assertIn("/api/analytics/track", api_map)
        self.assertEqual(api_map["/api/analytics/track"]["method"], "POST")
        self.assertIn("event", api_map["/api/analytics/track"]["params"])
        self.assertIn("ts", api_map["/api/analytics/track"]["params"])
        self.assertEqual(api_map["/api/analytics/track"]["source"], "JS_BEACON")

        self.assertIn("/sse/notifications", api_map)
        self.assertIn(api_map["/sse/notifications"]["method"], ("GET", "SSE"))
        self.assertEqual(api_map["/sse/notifications"]["source"], "JSLuice AST")

    def test_request_constructor_and_modern_clients(self):
        js_code = """
        const req = new Request("/api/v1/auth/refresh", {
            method: "POST",
            body: JSON.stringify({ refreshToken: "xyz" })
        });
        ky.post("/api/v1/payments", { json: { amount: 50, currency: "USD" } });
        superagent.post("/api/v1/feedback").send({ rating: 5, comment: "excellent" });
        """
        apis, routes, ws, cfgs, crefs = analyze_javascript_requests(js_code, "example.com")
        api_map = {a["url"]: a for a in apis}

        self.assertIn("/api/v1/auth/refresh", api_map)
        self.assertEqual(api_map["/api/v1/auth/refresh"]["method"], "POST")
        self.assertIn("refreshToken", api_map["/api/v1/auth/refresh"]["params"])

        self.assertIn("/api/v1/payments", api_map)
        self.assertEqual(api_map["/api/v1/payments"]["method"], "POST")
        self.assertIn("amount", api_map["/api/v1/payments"]["params"])

        self.assertIn("/api/v1/feedback", api_map)
        self.assertEqual(api_map["/api/v1/feedback"]["method"], "POST")
        self.assertIn("rating", api_map["/api/v1/feedback"]["params"])

    def test_template_literals(self):
        js_code = """
        const orgId = "org_1";
        const projId = "proj_2";
        fetch(`/api/v2/orgs/${orgId}/projects/${projId}/details`);
        """
        apis, routes, ws, cfgs, crefs = analyze_javascript_requests(js_code, "example.com")
        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["url"], "/api/v2/orgs/{orgId}/projects/{projId}/details")

    def test_dom_htmx_and_data_attributes(self):
        html = """
        <div hx-post="/api/htmx/vote" hx-vals='{"choice": 1, "pollId": 42}'>Vote</div>
        <div data-endpoint="/api/v1/stream">Stream</div>
        <router-link to="/admin/settings">Admin Settings</router-link>
        <link rel="service-worker" href="/service-worker.js">
        """
        parser = DOMSourceParser("https://example.com")
        parser.feed(html)

        self.assertEqual(len(parser.dom_api_endpoints), 2)
        htmx_ep = next(e for e in parser.dom_api_endpoints if e["url"] == "/api/htmx/vote")
        self.assertEqual(htmx_ep["method"], "POST")
        self.assertIn("choice", htmx_ep["params"])
        self.assertIn("pollId", htmx_ep["params"])

        data_ep = next(e for e in parser.dom_api_endpoints if e["url"] == "/api/v1/stream")
        self.assertEqual(data_ep["method"], "GET")

        self.assertIn("/admin/settings", parser.dom_app_routes)
        self.assertIn("/service-worker.js", parser.dom_config_refs)

    def test_scope_control(self):
        # External third-party calls must be excluded
        js_code = """
        fetch("https://server.ethicalads.io/api/v1/ads");
        fetch("https://2p66nmmycsj3.statuspage.io/api/v2/summary.json");
        fetch("https://api.example.com/v1/valid");
        fetch("/api/local/endpoint");
        """
        apis, routes, ws, cfgs, crefs = analyze_javascript_requests(js_code, "example.com")
        urls = [a["url"] for a in apis]
        self.assertIn("https://api.example.com/v1/valid", urls)
        self.assertIn("/api/local/endpoint", urls)
        self.assertNotIn("https://server.ethicalads.io/api/v1/ads", urls)
        self.assertNotIn("https://2p66nmmycsj3.statuspage.io/api/v2/summary.json", urls)

    def test_fixture_a_authentication_application(self):
        html = """
        <form action="/auth/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
        </form>
        <script>
            fetch("/api/auth/login", { method: "POST" });
        </script>
        """
        parser = DOMSourceParser("https://example.test/")
        parser.feed(html)
        forms = filter_functional_forms(parser.forms)
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["action"], "/auth/login")

        apis, routes, ws, cfgs, crefs = analyze_javascript_requests(parser.inline_scripts[0], "example.test")
        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["url"], "/api/auth/login")
        self.assertEqual(apis[0]["method"], "POST")

    def test_fixture_b_spa_application(self):
        js_code = """
        function goToDashboard() {
            window.location = "/dashboard";
        }
        fetch("/api/v1/users");
        axios.post("/api/v1/upload", { file: payload });
        """
        apis, routes, ws, cfgs, crefs = analyze_javascript_requests(js_code, "example.test")
        self.assertIn("/dashboard", routes)

        api_urls = [a["url"] for a in apis]
        api_methods = {a["url"]: a["method"] for a in apis}
        self.assertIn("/api/v1/users", api_urls)
        self.assertEqual(api_methods["/api/v1/users"], "GET")
        self.assertIn("/api/v1/upload", api_urls)
        self.assertEqual(api_methods["/api/v1/upload"], "POST")

    def test_fixture_c_configuration(self):
        js_code = """
        window.config = {
            API_BASE: "/api/v2",
            BACKEND_URL: "https://api.example.test",
            ENVIRONMENT: "staging",
            wsUrl: "wss://app.example.test/socket"
        };
        """
        apis, routes, ws, cfgs, crefs = analyze_javascript_requests(js_code, "example.test")
        self.assertEqual(cfgs.get("api_base"), "/api/v2")
        self.assertEqual(cfgs.get("backend_url"), "https://api.example.test")
        self.assertEqual(cfgs.get("environment"), "staging")
        self.assertIn("wss://app.example.test/socket", ws)

    def test_fixture_d_internal_exposure(self):
        text = """
        const internalIp = "10.10.20.15";
        const dbHost = "http://db01.internal.example";
        """
        hosts, buckets, sens = extract_infrastructure_and_sensitive(text, "test.js", "example.test")
        self.assertIn("10.10.20.15", hosts)
        self.assertIn("db01.internal.example", hosts)

    def test_fixture_e_source_map_validation(self):
        js_code = 'console.log("app");\n//# sourceMappingURL=/js/app.js.map'
        maps = extract_source_map_references(js_code, "https://example.test/js/app.js")
        self.assertEqual(len(maps), 1)
        self.assertEqual(maps[0][0], "/js/app.js.map")

    def test_technology_cross_reference_isolation(self):
        ev = detect_library_evidence("/assets/jquery-3.5.1.min.js", "/*! jQuery v3.5.1 */")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["name"], "jQuery")
        self.assertEqual(ev[0]["version"], "3.5.1")

        data = {
            "api_references": [{"method": "POST", "url": "/api/auth/login", "params": [], "display": "POST /api/auth/login"}],
            "technology_evidence": ev
        }
        buf = io.StringIO()
        test_console = Console(file=buf, force_terminal=False, no_color=True, highlight=False)
        with patch("openrecon.formatter.console", test_console):
            render_page_intel(data)

        output = buf.getvalue()
        self.assertIn("[+] Page Intelligence", output)
        self.assertIn("API Endpoint       POST /api/auth/login", output)
        self.assertNotIn("jQuery", output)
        self.assertNotIn("3.5.1", output)

    @patch("openrecon.modules.page_intel.safe_get")
    async def test_combined_realistic_application_flow(self, mock_safe_get):
        fixture_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <script src="https://cse.google.com/cse.js?cx=123"></script>
            <script src="/assets/jquery-3.5.1.min.js"></script>
            <script src="/js/config.js"></script>
            <script src="/js/app.js"></script>
            <link rel="service-worker" href="/sw.js">
        </head>
        <body>
            <div hx-post="/api/htmx/action" hx-vals='{"actionId": 99}'></div>
            <form action="/auth/login" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
            <script>
                function navigateDashboard() { window.location = "/dashboard"; }
                navigator.sendBeacon("/api/telemetry", JSON.stringify({ event: "init" }));
                fetch("/api/auth/login", {
                    method: "POST",
                    body: JSON.stringify({
                        username: username,
                        password: password
                    })
                });
            </script>
        </body>
        </html>
        """

        config_js = """
        window.APP_CONFIG = {
            API_BASE: "/api/v2",
            BACKEND_URL: "https://api.example.test",
            ENVIRONMENT: "staging",
            wsEndpoint: "wss://app.example.test/socket",
            internalServer: "10.10.20.15",
            dbHost: "http://db01.internal.example"
        };
        """

        app_js = """
        fetch("/api/v1/users");
        axios.post("/api/v1/upload", { file: data });
        //# sourceMappingURL=/js/app.js.map
        """

        map_json = json.dumps({
            "version": 3,
            "sources": ["app.ts"],
            "sourcesContent": ["console.log('SPA App');"]
        })

        async def mock_get(url, headers=None):
            if "app.js.map" in url:
                return {"status_code": 200, "content_text": map_json}
            elif "app.js" in url:
                return {"status_code": 200, "content_text": app_js}
            elif "config.js" in url:
                return {"status_code": 200, "content_text": config_js}
            elif "jquery-3.5.1.min.js" in url:
                return {"status_code": 200, "content_text": "/*! jQuery v3.5.1 */"}
            elif "cse.js" in url:
                return {"status_code": 200, "content_text": "console.log('google cse');"}
            return {"status_code": 200, "content_text": fixture_html}

        mock_safe_get.side_effect = mock_get

        res = await analyze_page_intel("example.test")

        self.assertEqual(len(res["forms"]), 1)
        self.assertEqual(res["forms"][0]["action"], "/auth/login")

        api_urls = [a["url"] for a in res["api_references"]]
        self.assertIn("/api/auth/login", api_urls)
        self.assertIn("/api/v1/users", api_urls)
        self.assertIn("/api/v1/upload", api_urls)
        self.assertIn("/api/htmx/action", api_urls)
        self.assertIn("/api/telemetry", api_urls)

        auth_api = next(a for a in res["api_references"] if a["url"] == "/api/auth/login")
        self.assertIn("username", auth_api["params"])
        self.assertIn("password", auth_api["params"])

        telemetry_api = next(a for a in res["api_references"] if a["url"] == "/api/telemetry")
        self.assertIn("event", telemetry_api["params"])

        htmx_api = next(a for a in res["api_references"] if a["url"] == "/api/htmx/action")
        self.assertIn("actionId", htmx_api["params"])

        self.assertIn("/dashboard", res["application_paths"])
        self.assertEqual(res["client_config"]["api_base"], "/api/v2")
        self.assertEqual(res["client_config"]["backend_url"], "https://api.example.test")
        self.assertEqual(res["client_config"]["environment"], "staging")
        self.assertIn("wss://app.example.test/socket", res["websockets"])
        self.assertIn("10.10.20.15", res["internal_hosts"])
        self.assertIn("db01.internal.example", res["internal_hosts"])
        self.assertEqual(res["source_maps"], ["/js/app.js.map (ACCESSIBLE, SOURCES PRESENT)"])
        self.assertIn("/sw.js", res["config_references"])
        self.assertEqual(len(res["technology_evidence"]), 1)
        self.assertEqual(res["technology_evidence"][0]["name"], "jQuery")


    def test_route_classification_filters_docs_blogs_jobs(self):
        hrefs = [
            "https://blog.python.org/",
            "https://docs.python.org/",
            "https://jobs.python.org/",
            "https://devguide.python.org/",
            "https://status.python.org/",
            "https://donate.python.org/",
            "https://peps.python.org/",
            "https://wiki.python.org/moin/",
            "https://www.python.org/psf/",
            "/about/",
            "/downloads/",
            "/community/",
            "/admin/login",
            "/account/settings"
        ]
        routes = extract_meaningful_app_routes(hrefs, "https://python.org")
        self.assertIn("/admin/login", routes)
        self.assertIn("/account/settings", routes)
        self.assertNotIn("https://blog.python.org/", routes)
        self.assertNotIn("https://docs.python.org/", routes)
        self.assertNotIn("https://jobs.python.org/", routes)
        self.assertNotIn("https://devguide.python.org/", routes)
        self.assertNotIn("https://status.python.org/", routes)
        self.assertNotIn("https://donate.python.org/", routes)

    def test_bmsit_real_html_fixture(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>BMSIT</title></head>
        <body>
            <a href="admissions.php">Admissions</a>
            <a href="career.php">Careers</a>
            <a href="admission-query.php">Query</a>
            <a href="https://staff.bmsit.ac.in/sims/index.php">SIMS Staff Portal</a>
            <a href="https://student.bmsit.ac.in/">Student Portal</a>
            <a href="https://results.bmsit.ac.in/">Results Portal</a>
            <a href="https://projects.bmsit.ac.in/grievance">Grievance Portal</a>
            <a href="https://www.facebook.com/bmsit">External FB</a>
            <a href="https://x.com/bmsitm1">External X</a>
            <!-- <form action="contact-enquiry.php" method="POST"><input name="email"></form> -->
        </body>
        </html>
        """
        parser = DOMSourceParser("https://bmsit.ac.in/")
        parser.feed(html)
        routes = extract_meaningful_app_routes(parser.href_links, "https://bmsit.ac.in/")
        
        self.assertIn("/admission-query.php", routes)
        self.assertIn("https://staff.bmsit.ac.in/sims/index.php", routes)
        self.assertIn("https://student.bmsit.ac.in/", routes)
        self.assertIn("https://results.bmsit.ac.in/", routes)
        self.assertIn("https://projects.bmsit.ac.in/grievance", routes)
        
        # General marketing/informational pages must not be treated as application routes
        self.assertNotIn("/admissions.php", routes)
        self.assertNotIn("/career.php", routes)
        self.assertNotIn("https://www.facebook.com/bmsit", routes)
        self.assertNotIn("https://x.com/bmsitm1", routes)

        forms = filter_functional_forms(parser.forms)
        self.assertEqual(len(forms), 0)

    def test_exposed_token_signatures(self):
        slack_path = "/".join(["services", "T00000000", "B00000000"]) + "/FakeWebhookSlackTestValu"
        slack_url = "https://" + "hooks." + "slack.com/" + slack_path
        js_code = f"""
        const firebaseConfig = {{
            apiKey: "AIzaSyA_8Hj9K2LmNpQrStUvWxYz0123456789A",
            authDomain: "my-app.firebaseapp.com"
        }};
        const stripe = Stripe("pk_live_51HzT9kL2k9jLmNpQrStUvWxYz0123456789ABCDEF");
        Sentry.init({{
            dsn: "https://a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4@o12345.ingest.sentry.io/54321"
        }});
        const mapboxToken = "pk.eyJ1FakeTokenForTestingPurposesOnlyToSatisfyRegexLengthAndAvoidSecretDetection";
        const cognitoPool = "us-east-1:12345678-abcd-1234-abcd-1234567890ab";
        const slackWebhook = "{slack_url}";
        """
        hosts, buckets, sens = extract_infrastructure_and_sensitive(js_code, "app.js", "example.com")
        
        sens_str = " ".join(sens)
        self.assertIn("Google / Firebase API Key", sens_str)
        self.assertIn("AIzaSy", sens_str)
        self.assertIn("Stripe Publishable Key", sens_str)
        self.assertIn("pk_live_51HzT9kL2k9jLmNpQrStUvWxYz0123456789ABCDEF", sens_str)
        self.assertIn("Sentry DSN", sens_str)
        self.assertIn("ingest.sentry.io", sens_str)
        self.assertIn("Mapbox Access Token", sens_str)
        self.assertIn("AWS Cognito Identity Pool ID", sens_str)
        self.assertIn("Slack Incoming Webhook", sens_str)

        # Formatter test
        data = {"sensitive_references": sens}
        buf = io.StringIO()
        test_console = Console(file=buf, force_terminal=False, no_color=True, highlight=False)
        with patch("openrecon.formatter.console", test_console):
            render_page_intel(data)
        out = buf.getvalue()
        self.assertIn("Exposed Token", out)
        self.assertIn("Google / Firebase API Key", out)

    def test_graphql_operation_extraction(self):
        js_code = """
        import { gql } from '@apollo/client';

        const GET_USER_PROFILE = gql`
          query GetUserProfile($userId: ID!, $includeHistory: Boolean) {
            user(id: $userId) {
              id
              email
              role
            }
          }
        `;

        const UPDATE_ROLE = gql`
          mutation UpdateUserRole($userId: ID!, $role: String!) {
            setUserRole(userId: $userId, role: $role) {
              success
            }
          }
        `;

        const SUB = gql`
          subscription OnAlert($orgId: ID!) {
            securityAlert(orgId: $orgId) {
              msg
            }
          }
        `;
        """
        ops = extract_graphql_operations(js_code)
        self.assertEqual(len(ops), 3)
        displays = [op["display"] for op in ops]
        self.assertIn("QUERY GetUserProfile (userId, includeHistory)", displays)
        self.assertIn("MUTATION UpdateUserRole (userId, role)", displays)
        self.assertIn("SUBSCRIPTION OnAlert (orgId)", displays)

        # Formatter test
        data = {"graphql_operations": ops}
        buf = io.StringIO()
        test_console = Console(file=buf, force_terminal=False, no_color=True, highlight=False)
        with patch("openrecon.formatter.console", test_console):
            render_page_intel(data)
        out = buf.getvalue()
        self.assertIn("GraphQL Operation", out)
        self.assertIn("QUERY GetUserProfile (userId, includeHistory)", out)
        self.assertIn("MUTATION UpdateUserRole (userId, role)", out)

    def test_oauth_configuration_extraction(self):
        js_code = """
        const auth0Client = await createAuth0Client({
          domain: 'dev-tenant123.us.auth0.com',
          clientId: 'aBcDeFgHiJkLmNoPqRsTuVwX',
          authorizationParams: {
            redirect_uri: 'https://app.example.com/callback',
            scope: 'openid profile email offline_access'
          }
        });

        const msalConfig = {
          auth: {
            clientId: '11111111-2222-3333-4444-555555555555',
            authority: 'https://login.microsoftonline.com/99999999-8888-7777-6666-555555555555',
            redirectUri: '/auth/callback'
          }
        };
        """
        findings = extract_oauth_configurations(js_code)
        displays = [f["display"] for f in findings]
        
        self.assertIn("Auth0 Domain: dev-tenant123.us.auth0.com", displays)
        self.assertIn("OAuth Client ID: aBcDeFgHiJkLmNoPqRsTuVwX", displays)
        self.assertIn("OAuth Redirect URI: https://app.example.com/callback", displays)
        self.assertIn("OAuth Scope: openid profile email offline_access", displays)
        self.assertIn("Auth Domain / Issuer: https://login.microsoftonline.com/99999999-8888-7777-6666-555555555555", displays)

        # Formatter test
        data = {"oauth_configurations": findings}
        buf = io.StringIO()
        test_console = Console(file=buf, force_terminal=False, no_color=True, highlight=False)
        with patch("openrecon.formatter.console", test_console):
            render_page_intel(data)
        out = buf.getvalue()
        self.assertIn("OAuth Configuration", out)
        self.assertIn("Auth0 Domain: dev-tenant123.us.auth0.com", out)

    def test_client_integrations_extraction(self):
        js_code = """
        (function(w, d) {
            w.CollectId = "69e0772892f50c4b01737af9";
        })(window, document);
        window.voiceflow.chat.load({
            verify: { projectID: "65cb07eb931e5000085d7b5f" },
            url: "https://general-runtime.voiceflow.com"
        });
        """
        _, _, sens = extract_infrastructure_and_sensitive(js_code, "inline script #1", "example.com")
        self.assertTrue(any("Collect.chat ID" in s and "69e0772892f50c4b01737af9" in s for s in sens))
        self.assertTrue(any("Voiceflow Chatbot Project ID" in s and "65cb07eb931e5000085d7b5f" in s for s in sens))

    def test_browser_resource_sinks(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta http-equiv="refresh" content="5;url=/portal/dashboard">
        </head>
        <body>
            <button formaction="/api/v1/checkout" formmethod="POST">Buy Now</button>
            <iframe src="/auth/login-embed"></iframe>
        </body>
        </html>
        """
        parser = DOMSourceParser("https://example.com")
        parser.feed(html)
        
        api_urls = [ep["url"] for ep in parser.dom_api_endpoints]
        self.assertIn("/api/v1/checkout", api_urls)
        
        routes = list(parser.dom_app_routes)
        self.assertIn("/portal/dashboard", routes)
        self.assertIn("/auth/login-embed", routes)

    def test_jsluice_generalized_string_extraction(self):
        js_code = """
        const routeA = "/api/v2/products/lookup";
        const routeB = "/graphql";
        const routeC = "/auth/oauth/token";
        """
        apis, _, _, _, _ = analyze_javascript_requests(js_code, "example.com")
        urls = [a["url"] for a in apis]
        self.assertIn("/api/v2/products/lookup", urls)
        self.assertIn("/graphql", urls)
        self.assertIn("/auth/oauth/token", urls)

if __name__ == "__main__":
    unittest.main()
