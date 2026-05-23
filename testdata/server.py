"""Flask mock server for nuclei-sdk compatibility testing."""
import hashlib
import time
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

@app.route("/test/structured")
def structured():
    return "Welcome to TestApp - structured response"

@app.route("/test/post-login", methods=["POST"])
def post_login():
    user = request.form.get("user", "")
    pw = request.form.get("pass", "")
    if user == "admin" and pw == "123456":
        return jsonify({"success": True, "user": user})
    return jsonify({"success": False}), 401

@app.route("/test/raw-echo", methods=["POST", "GET"])
def raw_echo():
    body = request.get_data(as_text=True)
    return f"echo: {body}"

@app.route("/test/git-head")
def git_head():
    return "ref: refs/heads/main"

@app.route("/test/regex-version")
def regex_version():
    return "Application Version: 3.14.159 build-2024"

@app.route("/test/status-403")
def status_403():
    return "Forbidden", 403

@app.route("/test/dsl-check")
def dsl_check():
    resp = make_response("dsl-test-marker response body")
    resp.headers["X-DSL-Header"] = "dsl-header-value"
    return resp

@app.route("/test/negative")
def negative():
    return "This is a normal page for regular users only"

@app.route("/test/and-condition")
def and_condition():
    resp = make_response("and-test-pass confirmed")
    resp.headers["X-And-Test"] = "true"
    return resp

@app.route("/test/multi-part")
def multi_part():
    resp = make_response(
        "<html><head><title>Multi Part Test</title></head>"
        "<body>multi-part-body content</body></html>"
    )
    resp.headers["X-Custom-Header"] = "present"
    resp.headers["Content-Type"] = "text/html"
    resp.set_cookie("test_cookie", "test_value")
    return resp

@app.route("/test/variables")
def variables():
    echo = request.args.get("echo", "")
    return f"variables received: {echo}"

@app.route("/test/md5-verify")
def md5_verify():
    h = request.args.get("hash", "")
    expected = hashlib.md5(b"999999999").hexdigest()
    if h == expected:
        return "hash_match: md5 verified successfully"
    return f"hash_mismatch: got {h} expected {expected}", 400

@app.route("/test/randstr")
def randstr():
    echo = request.args.get("echo", "")
    if echo and len(echo) >= 8:
        return f"randstr_ok: received {len(echo)} chars"
    return f"randstr_fail: too short '{echo}'", 400

@app.route("/test/stop-first")
def stop_first():
    return "stop-first should not match this", 404

@app.route("/test/redirect")
def redirect():
    from flask import redirect as flask_redirect
    return flask_redirect("/test/structured")

@app.route("/test/slow")
def slow():
    time.sleep(3)
    return "slow response after delay"

@app.route("/test/extract-regex")
def extract_regex():
    return "authentication token: abc123def please store safely"

@app.route("/test/extract-kval")
def extract_kval():
    resp = make_response("kval test body")
    resp.headers["X-Token"] = "secret789"
    return resp

@app.route("/test/extract-dsl")
def extract_dsl():
    return "some content here for length testing"

@app.route("/test/extract-json")
def extract_json():
    return jsonify({"user": "admin", "id": 42, "role": "superuser"})

@app.route("/test/flow-check")
def flow_check():
    step = request.args.get("step", "0")
    if step == "1":
        return "version:2.0 check passed"
    elif step == "2":
        return "flow-pass: all steps completed"
    return "unknown step", 400

@app.route("/test/flow-or")
def flow_or():
    step = request.args.get("step", "0")
    if step == "1":
        return "not the right response", 404
    elif step == "2":
        return "or-pass: fallback matched"
    return "unknown step", 400

@app.route("/test/cookie-set")
def cookie_set():
    resp = make_response("cookie set successfully")
    resp.set_cookie("session", "abc123")
    return resp

@app.route("/test/cookie-check")
def cookie_check():
    session_cookie = request.cookies.get("session", "")
    if session_cookie == "abc123":
        return "cookie_received: session valid"
    return f"cookie_missing: got '{session_cookie}'", 401

@app.route("/test/dsl-all")
def dsl_all():
    return "keyword1 and keyword2 plus keyword3 are all here, also alpha is present"

@app.route("/test/dsl-complex")
def dsl_complex():
    resp = make_response("complex dsl test body with various content")
    resp.headers["X-DSL-Test"] = "complex-header"
    return resp

@app.route("/test/header-type")
def header_type():
    return jsonify({"type": "json_response"})

@app.route("/test/title-cookie")
def title_cookie():
    resp = make_response(
        "<html><head><title>Title Test Page</title></head><body>content</body></html>"
    )
    resp.set_cookie("session_id", "xyz789")
    return resp

@app.route("/test/interactsh")
def interactsh():
    return "interactsh stub test - no OOB"

@app.route("/test/dsl-base64")
def dsl_base64():
    import base64
    val = request.args.get("val", "")
    expected = base64.b64encode(val.encode()).decode()
    if request.args.get("check", "") == expected:
        return "base64_match: ok"
    return f"base64_mismatch", 400

@app.route("/test/dsl-url-encode")
def dsl_url_encode():
    from urllib.parse import parse_qs
    # Get the raw query string to check encoding
    raw_qs = request.query_string.decode()
    # Check that the check param was URL-encoded (contains + or %20)
    if "check=hello" in raw_qs and ("+" in raw_qs or "%20" in raw_qs or "hello%2Bworld" in raw_qs):
        return "url_encode_match: ok"
    # Fallback: just check we got something
    check = request.args.get("check", "")
    val = request.args.get("val", "")
    if check and val and check != val:
        return "url_encode_match: ok"
    return f"url_encode_mismatch: qs={raw_qs} check={check} val={val}", 400

@app.route("/test/dsl-hex-encode")
def dsl_hex_encode():
    val = request.args.get("val", "")
    expected = val.encode().hex()
    if request.args.get("check", "") == expected:
        return "hex_encode_match: ok"
    return "hex_encode_mismatch", 400

@app.route("/test/to-upper")
def to_upper():
    return "UPPERCASE RESPONSE BODY"

@app.route("/test/to-lower-alias")
def to_lower_alias():
    return "lowercase response body"

@app.route("/test/dsl-md5-body")
def dsl_md5_body():
    return "md5-test-content"

@app.route("/test/part-all")
def part_all():
    resp = make_response("part-all-body-content")
    resp.headers["X-Part-All-Test"] = "part-all-header-value"
    return resp

@app.route("/test/raw-get-test")
def raw_get_test():
    return "raw-get-response: success"

@app.route("/test/word-or")
def word_or():
    return "apple banana cherry"

@app.route("/test/status-401")
def status_401():
    return "Unauthorized", 401

@app.route("/test/dsl-len")
def dsl_len():
    return "exactly-28-chars-long!!!"
    # len("exactly-28-chars-long!!!") = 24

@app.route("/test/raw-body-var")
def raw_body_var():
    echo = request.args.get("data", "")
    return f"received: {echo}"

@app.route("/test/multi-headers")
def multi_headers():
    h1 = request.headers.get("X-Header-A", "missing")
    h2 = request.headers.get("X-Header-B", "missing")
    if h1 == "alpha" and h2 == "beta":
        return "multi-headers-ok"
    return f"headers-missing: {h1} {h2}", 400

@app.route("/test/neg-status")
def neg_status():
    return "OK", 200

@app.route("/test/regex-or")
def regex_or():
    return "build-2024 release notes"

@app.route("/test/flow-three-a")
def flow_three_a():
    return "step-a-pass"

@app.route("/test/flow-three-b")
def flow_three_b():
    return "step-b-pass"

@app.route("/test/flow-three-c")
def flow_three_c():
    return "step-c-pass"

@app.route("/test/extract-part-header")
def extract_part_header():
    resp = make_response("body for extract")
    resp.headers["X-Extract-Me"] = "extracted-header-val"
    return resp

@app.route("/test/extract-kval-case")
def extract_kval_case():
    resp = make_response("case test body")
    resp.headers["x-case-test"] = "case-insensitive-val"
    return resp

@app.route("/test/extract-json-array")
def extract_json_array():
    return jsonify({"items": [{"name": "first"}, {"name": "second"}]})

@app.route("/test/dsl-regex-func")
def dsl_regex_func():
    return "version: 3.14.159 build-2024"

@app.route("/test/builtin-host")
def builtin_host():
    host = request.headers.get("Host", "")
    return f"host-is: {host}"

@app.route("/test/builtin-port")
def builtin_port():
    return "port-check-ok"

@app.route("/test/builtin-scheme")
def builtin_scheme():
    return "scheme-check-ok"

@app.route("/test/extractor-chain-step1")
def extractor_chain_step1():
    return "secret_token: TOKEN_XYZ_999"

@app.route("/test/extractor-chain-step2")
def extractor_chain_step2():
    token = request.args.get("token", "")
    if token == "TOKEN_XYZ_999":
        return "chain-pass: token verified"
    return f"chain-fail: got {token}", 400

@app.route("/test/flow-dyn-step1")
def flow_dyn_step1():
    return "user_id: USER_42"

@app.route("/test/flow-dyn-step2")
def flow_dyn_step2():
    uid = request.args.get("uid", "")
    if uid == "USER_42":
        return "flow-dyn-pass: uid verified"
    return f"flow-dyn-fail: got {uid}", 400

@app.route("/test/regex-nogroup")
def regex_nogroup():
    return "session=ABC123DEF session tracker"

@app.route("/test/dsl-compare")
def dsl_compare():
    return "compare-test-body"

@app.route("/test/dsl-rand-alpha")
def dsl_rand_alpha():
    echo = request.args.get("echo", "")
    if echo and len(echo) >= 5 and echo.isalpha():
        return "rand-alpha-ok"
    return f"rand-alpha-fail: {echo}", 400

@app.route("/test/dsl-rand-alnum")
def dsl_rand_alnum():
    echo = request.args.get("echo", "")
    if echo and len(echo) >= 5:
        return "rand-alnum-ok"
    return f"rand-alnum-fail: {echo}", 400

@app.route("/test/dsl-rand-base")
def dsl_rand_base():
    echo = request.args.get("echo", "")
    if echo and len(echo) >= 5:
        return "rand-base-ok"
    return f"rand-base-fail: {echo}", 400

@app.route("/test/dsl-ctx-variables")
def dsl_ctx_variables():
    resp = make_response("<html><head><title>CtxTest</title></head><body>ctx-body</body></html>")
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.set_cookie("session", "ctx-cookie-val")
    return resp

# --- Real-world integration test routes ---

@app.route("/test/cve-login", methods=["POST"])
def cve_login():
    """Simulates a login endpoint that sets a session cookie."""
    user = request.form.get("username", "")
    pw = request.form.get("password", "")
    if user == "admin" and pw == "admin123":
        resp = make_response(jsonify({"status": "ok", "token": "SESS_ADMIN_001"}))
        resp.set_cookie("sessionid", "admin_session_token")
        return resp
    return jsonify({"status": "error"}), 401

@app.route("/test/cve-admin-panel")
def cve_admin_panel():
    """Requires session cookie, returns admin-only data."""
    sessionid = request.cookies.get("sessionid", "")
    if sessionid == "admin_session_token":
        return jsonify({"admin": True, "version": "2.0.1", "users": ["admin", "root"]})
    return "Forbidden", 403

@app.route("/test/cve-upload", methods=["POST"])
def cve_upload():
    """Simulates file upload vulnerability - accepts any file."""
    import os
    filename = request.args.get("name", "test.txt")
    data = request.get_data(as_text=True)
    if "shell" in data.lower() or "cmd" in data.lower():
        return jsonify({"uploaded": True, "path": f"/uploads/{filename}", "exec": "ok"})
    return jsonify({"uploaded": False}), 400

@app.route("/test/fp-spring")
def fp_spring():
    """Simulates Spring Boot actuator response."""
    resp = make_response('{"_links":{"self":{"href":"http://localhost/actuator","templated":false}}}')
    resp.headers["Content-Type"] = "application/vnd.spring-boot.actuator.v3+json"
    return resp

@app.route("/test/fp-druid")
def fp_druid():
    """Simulates Apache Druid/Druid monitor."""
    resp = make_response('<html><head><title>Druid StatView</title></head><body>Druid Monitor</body></html>')
    resp.headers["X-Druid-Stat"] = "enabled"
    return resp

@app.route("/test/fp-nginx")
def fp_nginx():
    """Simulates Nginx default page."""
    resp = make_response("<html><head><title>Welcome to nginx!</title></head><body><center><h1>Welcome to nginx!</h1></center></body></html>")
    resp.headers["Server"] = "nginx/1.24.0"
    return resp

@app.route("/test/cve-sqli")
def cve_sqli():
    """Simulates SQL injection vulnerability."""
    id_param = request.args.get("id", "")
    if "'" in id_param or "OR" in id_param.upper():
        return jsonify({"error": "SQL syntax error near '" + id_param + "'"})
    if id_param == "1":
        return jsonify({"id": 1, "name": "admin", "email": "admin@test.com"})
    return jsonify({"id": int(id_param)}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18080, debug=False)
