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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18080, debug=False)
