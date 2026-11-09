from flask import Flask, request, Response
import requests
from urllib.parse import urlparse

app = Flask(__name__)

# Allowlist (deny-by-default) - tylko te hosty wolno pobierac
ALLOWED_HOSTS = {"api.internal.local"}   # celowo NIE zawiera example/httpbin/google

@app.route("/")
def index():
    return """
    <h1>SSRF Demo App (fixed)</h1>
    <p>/fetch akceptuje tylko hosty z allowlisty.</p>
    """

@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    if not url:
        return "Provide a URL", 400

    # Walidacja URL wzgledem allowlisty (deny by default)
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        return f"Forbidden: host '{host}' is not in the allowlist", 403

    try:
        # bez przekierowan (mozna je wykorzystac do obejscia) + timeout
        resp = requests.get(url, allow_redirects=False, timeout=3)
        return Response(resp.content, content_type=resp.headers.get("Content-Type", "text/html"))
    except Exception as e:
        return f"Error: {e}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
