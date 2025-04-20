import requests
import re
import concurrent.futures

# Framework fingerprinting data
FRAMEWORKS = {
    "Spring Boot": {
        "headers": ["X-Application-Context"],
        "error_patterns": ["Whitelabel Error Page"],
        "endpoints": ["/actuator", "/actuator/health", "/actuator/info", "/error" , "/actuator/env",
    "/actuator/metrics", "/actuator/loggers", "/actuator/mappings" , "/actuator%72" , "/actuator%2572", "/actuator/favicon.ico", "/favicon.ico"]
    },
    "Django": {
        "headers": ["X-Frame-Options"],
        "error_patterns": ["<title>Server Error (500)</title>"],
        "endpoints": ["/admin", "/static/admin/", "/healthz"]
    },
    "Flask": {
        "headers": ["X-Powered-By"],
        "error_patterns": ["Werkzeug Debugger", "The requested URL was not found on the server"],
        "endpoints": ["/debug", "/api", "/static"]
    },
    "Express.js": {
        "headers": ["X-Powered-By"],
        "error_patterns": ["Cannot GET /nonexistentpage"],
        "endpoints": ["/api", "/health", "/status"]
    },
    "Ruby on Rails": {
        "headers": ["X-Runtime", "X-Request-Id"],
        "error_patterns": ["Routing Error", "No route matches"],
        "endpoints": ["/rails/info/properties", "/assets", "/health_check"]
    },
    "ASP.NET Core": {
        "headers": ["Server"],
        "error_patterns": ["An unhandled exception occurred while processing the request"],
        "endpoints": ["/swagger", "/api/health", "/index"]
    },
    "Laravel": {
        "headers": ["X-Powered-By", "X-Laravel"],
        "error_patterns": ["Whoops, looks like something went wrong"],
        "endpoints": ["/api", "/artisan", "/storage/logs"]
    },
    "Symfony": {
        "headers": ["X-Debug-Token", "X-Debug-Token-Link"],
        "error_patterns": ["Symfony Exception"],
        "endpoints": ["/_profiler", "/config", "/phpinfo"]
    },
    "WordPress": {
        "headers": ["X-Pingback"],
        "error_patterns": ["wp-content", "wp-includes"],
        "endpoints": ["/wp-json", "/wp-admin", "/wp-content"]
    },
    "FastAPI": {
        "headers": ["server", "x-process-time"],
        "error_patterns": ["FastAPI"],
        "endpoints": ["/docs", "/redoc", "/openapi.json"]
    }
}

def check_headers(response, framework, results):
    """Check if response headers match a known framework."""
    for header in FRAMEWORKS[framework]["headers"]:
        if header in response.headers:
            results[framework]["headers"].append(header)

def check_error_patterns(response, framework, results):
    """Check if response body contains a known error pattern."""
    for pattern in FRAMEWORKS[framework]["error_patterns"]:
        if re.search(pattern, response.text, re.IGNORECASE):
            results[framework]["errors"].append(pattern)

def check_endpoints(base_url, framework, results):
    """Check framework-specific endpoints."""
    endpoints = FRAMEWORKS[framework]["endpoints"]
    for endpoint in endpoints:
        url = base_url.rstrip("/") + endpoint
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                results[framework]["urls"].append(url)
        except requests.exceptions.RequestException:
            pass

def scan_framework(base_url):
    """Scan a website for various web frameworks."""
    print(f"\n[🔍 Scanning {base_url} for Web Frameworks...]\n")
    
    results = {framework: {"headers": [], "errors": [], "urls": []} for framework in FRAMEWORKS}

    try:
        response = requests.get(base_url, timeout=3)
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to reach {base_url}: {e}")
        return

    for framework in FRAMEWORKS.keys():
        check_headers(response, framework, results)
        check_error_patterns(response, framework, results)

    # Run endpoint checks concurrently
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_endpoints, base_url, framework, results): framework for framework in FRAMEWORKS.keys()}
        for future in concurrent.futures.as_completed(futures):
            pass

    found_any = False

    print("\n[🔎 Scan Results]\n")
    for framework, data in results.items():
        if data["headers"] or data["errors"] or data["urls"]:
            found_any = True
            print(f"\n🔥 **{framework} Detected!** 🔥")

            if data["headers"]:
                print("  📌 Headers:")
                for header in data["headers"]:
                    print(f"    - {header}")

            if data["errors"]:
                print("  ❌ Error Patterns:")
                for pattern in data["errors"]:
                    print(f"    - {pattern}")

            if data["urls"]:
                print("  🌐 Endpoints Found:")
                for url in data["urls"]:
                    print(f"    - {url}")

    if not found_any:
        print("[-] No known framework detected.")

    print("\n✅ Scan complete.")

def main():
    base_url = input("Enter target URL (e.g., https://example.com): ").strip()
    scan_framework(base_url)

if __name__ == "__main__":
    main()
