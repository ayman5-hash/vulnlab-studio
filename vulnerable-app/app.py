from flask import (
    Flask,
    request,
    session,
    redirect,
    jsonify,
    make_response,
    render_template,
)

import html
import json
import os
import sqlite3
import time
import urllib.request


app = Flask(__name__)
app.secret_key = "VULNLAB-LAB-ONLY-CHANGE-ME"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vulnlab.db")
LAB_DIR = os.path.join(BASE_DIR, "lab_files")
PUBLIC_DIR = os.path.join(BASE_DIR, "public_files")

FAILED = {}


# ============================================================
# DATABASE
# ============================================================

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            category TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            body TEXT
        )
    """)

    cur.execute("""
        INSERT OR IGNORE INTO users(id, username, password)
        VALUES(1, 'lab-student', 'lab123')
    """)

    cur.execute("""
        INSERT OR IGNORE INTO products(id, name, category)
        VALUES(1, 'Keyboard', 'hardware')
    """)

    cur.execute("""
        INSERT OR IGNORE INTO products(id, name, category)
        VALUES(2, 'Mouse', 'hardware')
    """)

    con.commit()
    con.close()


# ============================================================
# HELPERS
# ============================================================

def difficulty():
    value = request.args.get("level", "easy").lower()

    allowed = {
        "easy",
        "medium",
        "hard",
        "expert",
    }

    return value if value in allowed else "easy"


def raw_mode():
    return request.args.get("raw", "0") == "1"


def render_lab(
    *,
    lab_type,
    lab_title,
    lab_category,
    cwe,
    description,
    level,
    action,
    current_value="",
    result="No request executed yet.",
    default_query="",
):
    return render_template(
        "lab.html",
        lab_type=lab_type,
        lab_title=lab_title,
        lab_category=lab_category,
        cwe=cwe,
        description=description,
        level=level,
        action=action,
        current_value=current_value,
        result=result,
        default_query=default_query,
    )


# ============================================================
# HOME
# ============================================================

@app.get("/")
def index():
    return render_template("index.html")


# ============================================================
# AUTHENTICATION LAB
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    level = difficulty()

    if request.method == "GET":
        return render_template(
            "login.html",
            level=level,
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    key = username or request.remote_addr or "unknown"

    FAILED.setdefault(key, 0)

    # Medium: petit délai progressif.
    if level == "medium" and FAILED[key] >= 2:
        time.sleep(0.6)

    # Hard / Expert: verrouillage simulé.
    if level in {"hard", "expert"} and FAILED[key] >= 4:
        response = make_response(
            "Authentication failed",
            429,
        )

        response.headers["Retry-After"] = "20"

        return response

    con = sqlite3.connect(DB_PATH)

    user = con.execute(
        """
        SELECT id
        FROM users
        WHERE username = ?
        AND password = ?
        """,
        (username, password),
    ).fetchone()

    con.close()

    if user:
        FAILED[key] = 0
        session["user_id"] = user[0]

        if level == "expert":
            session["mfa_pending"] = True
            return "MFA challenge required", 202

        return redirect("/")

    FAILED[key] += 1

    if level == "easy":
        if username != "lab-student":
            return "Unknown user", 401

        return "Wrong password", 401

    return "Authentication failed", 401


# ============================================================
# XSS LAB
# ============================================================

@app.get("/labs/xss")
def xss():
    q = request.args.get("q", "")
    level = difficulty()

    # --------------------------------------------------------
    # EASY
    # --------------------------------------------------------

    if level == "easy":

        # raw=1 conserve une véritable réflexion directe
        # réservée au laboratoire contrôlé.
        if raw_mode():
            return f"""
            <!doctype html>
            <html>
            <body>
                <h2>Result</h2>
                <div>{q}</div>
            </body>
            </html>
            """

        result = (
            q
            if q
            else "Enter a controlled value and execute the request."
        )

        return render_lab(
            lab_type="xss",
            lab_title="Cross-Site Scripting",
            lab_category="OUTPUT INJECTION",
            cwe="CWE-79",
            description=(
                "Controlled reflected XSS scenario used for "
                "output-context and reflection analysis."
            ),
            level=level,
            action="/labs/xss",
            current_value=q,
            result=result,
            default_query="q=test",
        )

    # --------------------------------------------------------
    # MEDIUM
    # --------------------------------------------------------

    if level == "medium":

        partially_filtered = (
            q.replace("<script>", "")
             .replace("</script>", "")
        )

        if raw_mode():
            return f"""
            <!doctype html>
            <html>
            <body>
                <h2>Filtered Result</h2>
                <div>{partially_filtered}</div>
            </body>
            </html>
            """

        result = (
            partially_filtered
            if q
            else "Enter a value to observe partial filtering."
        )

        return render_lab(
            lab_type="xss",
            lab_title="Cross-Site Scripting",
            lab_category="PARTIAL FILTERING",
            cwe="CWE-79",
            description=(
                "Reflected XSS scenario using deliberately "
                "incomplete filtering."
            ),
            level=level,
            action="/labs/xss",
            current_value=q,
            result=result,
            default_query="q=test",
        )

    # --------------------------------------------------------
    # HARD
    # --------------------------------------------------------

    if level == "hard":

        if request.args.get("store") == "1":
            con = sqlite3.connect(DB_PATH)

            con.execute(
                "INSERT INTO notes(body) VALUES(?)",
                (q,),
            )

            con.commit()
            con.close()

            if raw_mode():
                return "stored"

            result = "Value stored successfully."

        else:
            con = sqlite3.connect(DB_PATH)

            rows = con.execute(
                """
                SELECT body
                FROM notes
                ORDER BY id DESC
                LIMIT 5
                """
            ).fetchall()

            con.close()

            rendered = "\n".join(
                row[0]
                for row in rows
            )

            if raw_mode():
                return f"""
                <!doctype html>
                <html>
                <body>
                    <h2>Stored Notes</h2>
                    <div>{rendered}</div>
                </body>
                </html>
                """

            result = rendered if rendered else "No stored values yet."

        return render_lab(
            lab_type="xss",
            lab_title="Stored Cross-Site Scripting",
            lab_category="STORED OUTPUT",
            cwe="CWE-79",
            description=(
                "Stored XSS scenario where submitted values "
                "are persisted and rendered later."
            ),
            level=level,
            action="/labs/xss",
            current_value=q,
            result=result,
            default_query="q=test",
        )

    # --------------------------------------------------------
    # EXPERT
    # --------------------------------------------------------

    if request.args.get("prepare") == "1":
        session["xss_ready"] = True

        if raw_mode():
            return "prepared"

        return render_lab(
            lab_type="xss",
            lab_title="Contextual Cross-Site Scripting",
            lab_category="STATEFUL JAVASCRIPT CONTEXT",
            cwe="CWE-79",
            description=(
                "Stateful XSS scenario requiring contextual "
                "JavaScript analysis."
            ),
            level=level,
            action="/labs/xss",
            current_value=q,
            result="Session prepared. Execute the main request.",
            default_query="q=test",
        )

    if not session.get("xss_ready"):

        if raw_mode():
            return "prepare required", 403

        return render_lab(
            lab_type="xss",
            lab_title="Contextual Cross-Site Scripting",
            lab_category="STATEFUL JAVASCRIPT CONTEXT",
            cwe="CWE-79",
            description=(
                "Stateful XSS scenario requiring contextual "
                "JavaScript analysis."
            ),
            level=level,
            action="/labs/xss",
            current_value=q,
            result="State required. Prepare the session first.",
            default_query="q=test",
        )

    if raw_mode():
        return f"""
        <!doctype html>
        <html>
        <body>
            <script>
                const labValue = '{q}';
                document.body.dataset.labValue = labValue;
            </script>
        </body>
        </html>
        """

    return render_lab(
        lab_type="xss",
        lab_title="Contextual Cross-Site Scripting",
        lab_category="STATEFUL JAVASCRIPT CONTEXT",
        cwe="CWE-79",
        description=(
            "Stateful XSS scenario requiring contextual "
            "JavaScript analysis."
        ),
        level=level,
        action="/labs/xss",
        current_value=q,
        result=f"JavaScript context:\nconst labValue = '{q}';",
        default_query="q=test",
    )


# ============================================================
# SQL INJECTION LAB
# ============================================================

@app.get("/labs/sqli")
def sqli():
    product_id = request.args.get("id", "1")
    level = difficulty()

    con = sqlite3.connect(DB_PATH)

    if level == "expert" and not session.get("sqli_ready"):

        if request.args.get("prepare") == "1":
            session["sqli_ready"] = True
            con.close()

            if raw_mode():
                return jsonify({"prepared": True})

            return render_lab(
                lab_type="sqli",
                lab_title="SQL Injection",
                lab_category="STATEFUL DATABASE BEHAVIOR",
                cwe="CWE-89",
                description=(
                    "Expert SQL injection scenario requiring "
                    "prior application state."
                ),
                level=level,
                action="/labs/sqli",
                current_value=product_id,
                result="Session prepared. Execute the SQL lab request.",
                default_query="id=1",
            )

        con.close()

        if raw_mode():
            return jsonify({
                "error": "state required"
            }), 403

        return render_lab(
            lab_type="sqli",
            lab_title="SQL Injection",
            lab_category="STATEFUL DATABASE BEHAVIOR",
            cwe="CWE-89",
            description=(
                "Expert SQL injection scenario requiring "
                "prior application state."
            ),
            level=level,
            action="/labs/sqli",
            current_value=product_id,
            result="State required. Prepare the session first.",
            default_query="id=1",
        )

    try:

        if level == "medium":
            query = (
                "SELECT id, name, category "
                "FROM products "
                "WHERE id='" + product_id + "'"
            )
        else:
            query = (
                "SELECT id, name, category "
                "FROM products "
                "WHERE id=" + product_id
            )

        rows = con.execute(query).fetchall()
        con.close()

        payload = {
            "rows": rows,
            "count": len(rows),
        }

        if raw_mode():
            return jsonify(payload)

        if level == "easy":
            category = "ERROR-BASED SQL BEHAVIOR"
        elif level == "medium":
            category = "QUOTED SQL CONTEXT"
        elif level == "hard":
            category = "BLIND DIFFERENTIAL BEHAVIOR"
        else:
            category = "STATEFUL DATABASE BEHAVIOR"

        return render_lab(
            lab_type="sqli",
            lab_title="SQL Injection",
            lab_category=category,
            cwe="CWE-89",
            description=(
                "Controlled SQL injection laboratory based on "
                "response errors and differential behavior."
            ),
            level=level,
            action="/labs/sqli",
            current_value=product_id,
            result=json.dumps(
                payload,
                indent=2,
            ),
            default_query="id=1",
        )

    except Exception as exc:
        con.close()

        if level in {"hard", "expert"}:
            payload = {
                "rows": [],
                "count": 0,
            }

            if raw_mode():
                return jsonify(payload), 200

            result = json.dumps(
                payload,
                indent=2,
            )

        else:
            payload = {
                "error": str(exc)
            }

            if raw_mode():
                return jsonify(payload), 500

            result = json.dumps(
                payload,
                indent=2,
            )

        return render_lab(
            lab_type="sqli",
            lab_title="SQL Injection",
            lab_category="DATABASE RESPONSE ANALYSIS",
            cwe="CWE-89",
            description=(
                "Controlled SQL injection laboratory based on "
                "response errors and differential behavior."
            ),
            level=level,
            action="/labs/sqli",
            current_value=product_id,
            result=result,
            default_query="id=1",
        )


# ============================================================
# LOCAL FILE INCLUSION LAB
# ============================================================

@app.get("/labs/lfi")
def lfi():
    name = request.args.get("name", "")
    level = difficulty()

    if level == "expert" and not session.get("file_ready"):

        if request.args.get("prepare") == "1":
            session["file_ready"] = True

            if raw_mode():
                return "prepared"

            return render_lab(
                lab_type="lfi",
                lab_title="Local File Inclusion",
                lab_category="STATEFUL FILE ACCESS",
                cwe="CWE-98",
                description=(
                    "Controlled local file scenario using "
                    "dedicated laboratory marker files."
                ),
                level=level,
                action="/labs/lfi",
                current_value=name,
                result="Session prepared. Execute the LFI request.",
                default_query="name=lfi-marker.txt",
            )

        if raw_mode():
            return "state required", 403

        return render_lab(
            lab_type="lfi",
            lab_title="Local File Inclusion",
            lab_category="STATEFUL FILE ACCESS",
            cwe="CWE-98",
            description=(
                "Controlled local file scenario using "
                "dedicated laboratory marker files."
            ),
            level=level,
            action="/labs/lfi",
            current_value=name,
            result="State required. Prepare the session first.",
            default_query="name=lfi-marker.txt",
        )

    if level == "easy":
        path = os.path.join(
            LAB_DIR,
            name,
        )

    elif level == "medium":
        filtered_name = name.replace("../", "")

        path = os.path.join(
            LAB_DIR,
            filtered_name,
        )

    else:
        normalized_name = os.path.normpath(name)

        path = os.path.join(
            LAB_DIR,
            normalized_name,
        )

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:
            content = f.read()

        if raw_mode():
            return (
                content,
                200,
                {
                    "Content-Type": "text/plain"
                },
            )

        return render_lab(
            lab_type="lfi",
            lab_title="Local File Inclusion",
            lab_category="CONTROLLED FILE ACCESS",
            cwe="CWE-98",
            description=(
                "Controlled local file scenario using "
                "dedicated laboratory marker files."
            ),
            level=level,
            action="/labs/lfi",
            current_value=name,
            result=content,
            default_query="name=lfi-marker.txt",
        )

    except Exception as exc:
        result = f"File error: {exc}"

        if raw_mode():
            return result, 404

        return render_lab(
            lab_type="lfi",
            lab_title="Local File Inclusion",
            lab_category="CONTROLLED FILE ACCESS",
            cwe="CWE-98",
            description=(
                "Controlled local file scenario using "
                "dedicated laboratory marker files."
            ),
            level=level,
            action="/labs/lfi",
            current_value=name,
            result=result,
            default_query="name=lfi-marker.txt",
        )


# ============================================================
# PATH TRAVERSAL LAB
# ============================================================

@app.get("/labs/traversal")
def traversal():
    supplied = request.args.get("path", "")
    level = difficulty()

    if level == "expert" and not session.get("download_ready"):

        if request.args.get("prepare") == "1":
            session["download_ready"] = True

            if raw_mode():
                return "prepared"

            return render_lab(
                lab_type="traversal",
                lab_title="Path Traversal",
                lab_category="STATEFUL PATH ACCESS",
                cwe="CWE-22",
                description=(
                    "Controlled traversal scenario restricted "
                    "to the VulnLab filesystem structure."
                ),
                level=level,
                action="/labs/traversal",
                current_value=supplied,
                result="Session prepared. Execute the traversal request.",
                default_query="path=public_files/readme.txt",
            )

        if raw_mode():
            return "state required", 403

        return render_lab(
            lab_type="traversal",
            lab_title="Path Traversal",
            lab_category="STATEFUL PATH ACCESS",
            cwe="CWE-22",
            description=(
                "Controlled traversal scenario restricted "
                "to the VulnLab filesystem structure."
            ),
            level=level,
            action="/labs/traversal",
            current_value=supplied,
            result="State required. Prepare the session first.",
            default_query="path=public_files/readme.txt",
        )

    if level == "easy":
        path = os.path.join(
            BASE_DIR,
            supplied,
        )

    elif level == "medium":
        filtered_path = supplied.replace("../", "")

        path = os.path.join(
            BASE_DIR,
            filtered_path,
        )

    else:
        normalized_path = os.path.normpath(
            supplied
        )

        path = os.path.join(
            PUBLIC_DIR,
            normalized_path,
        )

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:
            content = f.read()

        if raw_mode():
            return (
                content,
                200,
                {
                    "Content-Type": "text/plain"
                },
            )

        return render_lab(
            lab_type="traversal",
            lab_title="Path Traversal",
            lab_category="FILESYSTEM PATH HANDLING",
            cwe="CWE-22",
            description=(
                "Controlled traversal scenario restricted "
                "to the VulnLab filesystem structure."
            ),
            level=level,
            action="/labs/traversal",
            current_value=supplied,
            result=content,
            default_query="path=public_files/readme.txt",
        )

    except Exception as exc:
        result = f"Path error: {exc}"

        if raw_mode():
            return result, 404

        return render_lab(
            lab_type="traversal",
            lab_title="Path Traversal",
            lab_category="FILESYSTEM PATH HANDLING",
            cwe="CWE-22",
            description=(
                "Controlled traversal scenario restricted "
                "to the VulnLab filesystem structure."
            ),
            level=level,
            action="/labs/traversal",
            current_value=supplied,
            result=result,
            default_query="path=public_files/readme.txt",
        )


# ============================================================
# CONTROLLED RFI LAB
# ============================================================

@app.get("/labs/rfi")
def rfi():
    url = request.args.get("url", "")
    level = difficulty()

    # Confinement obligatoire :
    # uniquement 127.0.0.1:9000.
    if not url.startswith(
        "http://127.0.0.1:9000/"
    ):
        result = (
            "Only controlled loopback resource server "
            "is allowed."
        )

        if raw_mode():
            return result, 403

        return render_lab(
            lab_type="rfi",
            lab_title="Controlled Remote File Inclusion",
            lab_category="LOOPBACK RESOURCE ACCESS",
            cwe="CWE-98",
            description=(
                "Remote-resource simulation strictly restricted "
                "to the local VulnLab resource server."
            ),
            level=level,
            action="/labs/rfi",
            current_value=url,
            result=result,
            default_query=(
                "url=http://127.0.0.1:9000/marker.txt"
            ),
        )

    if level == "expert" and not session.get("remote_ready"):

        if request.args.get("prepare") == "1":
            session["remote_ready"] = True

            if raw_mode():
                return "prepared"

            return render_lab(
                lab_type="rfi",
                lab_title="Controlled Remote File Inclusion",
                lab_category="STATEFUL REMOTE RESOURCE",
                cwe="CWE-98",
                description=(
                    "Remote-resource simulation strictly "
                    "restricted to the local resource server."
                ),
                level=level,
                action="/labs/rfi",
                current_value=url,
                result="Session prepared. Execute the RFI request.",
                default_query=(
                    "url=http://127.0.0.1:9000/marker.txt"
                ),
            )

        if raw_mode():
            return "state required", 403

        return render_lab(
            lab_type="rfi",
            lab_title="Controlled Remote File Inclusion",
            lab_category="STATEFUL REMOTE RESOURCE",
            cwe="CWE-98",
            description=(
                "Remote-resource simulation strictly restricted "
                "to the local VulnLab resource server."
            ),
            level=level,
            action="/labs/rfi",
            current_value=url,
            result="State required. Prepare the session first.",
            default_query=(
                "url=http://127.0.0.1:9000/marker.txt"
            ),
        )

    try:
        data = urllib.request.urlopen(
            url,
            timeout=2,
        ).read(4096)

        content = data.decode(
            "utf-8",
            errors="replace",
        )

        if raw_mode():
            return (
                data,
                200,
                {
                    "Content-Type": "text/plain"
                },
            )

        return render_lab(
            lab_type="rfi",
            lab_title="Controlled Remote File Inclusion",
            lab_category="LOOPBACK RESOURCE ACCESS",
            cwe="CWE-98",
            description=(
                "Remote-resource simulation strictly restricted "
                "to 127.0.0.1:9000."
            ),
            level=level,
            action="/labs/rfi",
            current_value=url,
            result=content,
            default_query=(
                "url=http://127.0.0.1:9000/marker.txt"
            ),
        )

    except Exception as exc:
        result = f"Remote error: {exc}"

        if raw_mode():
            return result, 502

        return render_lab(
            lab_type="rfi",
            lab_title="Controlled Remote File Inclusion",
            lab_category="LOOPBACK RESOURCE ACCESS",
            cwe="CWE-98",
            description=(
                "Remote-resource simulation strictly restricted "
                "to 127.0.0.1:9000."
            ),
            level=level,
            action="/labs/rfi",
            current_value=url,
            result=result,
            default_query=(
                "url=http://127.0.0.1:9000/marker.txt"
            ),
        )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    os.makedirs(
        LAB_DIR,
        exist_ok=True,
    )

    os.makedirs(
        PUBLIC_DIR,
        exist_ok=True,
    )

    init_db()

    print("=" * 60)
    print("VulnLab Target")
    print("http://127.0.0.1:8080")
    print("LAB USE ONLY")
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=8080,
        debug=False,
    )
