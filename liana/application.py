import json
from functools import wraps
from datetime import datetime

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)

from liana.db import get_db
from . import crypto
from . import lic as licmodule

bp = Blueprint("app", __name__)


def forwarded(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        request_uri = ""
        if "X-Forwarded-Request-Uri" in request.headers:
            request_uri = request.headers.get("X-Forwarded-Request-Uri")

        g.request_uri = request_uri

    return wrap


def authenticated(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        auth_email = ""
        if "X-Auth-Email" in request.headers:
            auth_email = request.headers.get("X-Auth-Email")

        g.auth_email = auth_email

    return wrap


@bp.route("/")
@authenticated
def index():
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.Algorithm AS algorithm,"
        " (SELECT COUNT(*) FROM License l WHERE l.AppCode = a.AppCode) AS lic"
        " FROM Application a"
        " ORDER BY a.AppCode ASC"
    )
    apps = cur.fetchall()
    return render_template("index.html", apps=apps)


@bp.route("/create", methods=("GET", "POST"))
@forwarded
@authenticated
def create():
    if request.method == "POST":
        code = request.form["appcode"]
        algorithm = request.form["algorithm"]
        createdby = request.form["createdby"]
        error = None

        if not code:
            error = "AppCode is required."

        if algorithm == "EC256":
            signaturekey = crypto.export_privkey(crypto.generate_ec256_privkey())
            privatekey = crypto.export_privkey(crypto.generate_ec256_privkey())

        elif algorithm == "Ed25519":
            signaturekey = crypto.export_privkey(crypto.generate_ed25519_privkey())
            privatekey = crypto.export_privkey(crypto.generate_x25519_privkey())

        else:
            error = "invalid Algorithm "

        if error is not None:
            flash(error)
        else:
            db = get_db()
            cur = db.cursor()
            cur.execute(
                "INSERT INTO Application (AppCode, SignatureKey, PrivateKey, Algorithm, CreatedBy)"
                " VALUES (%s, %s, %s, %s, %s)",
                (code, signaturekey, privatekey, algorithm, createdby),
            )
            db.commit()
            return redirect(g.request_uri + url_for("index"))

    return render_template("create.html")


def get_post(appcode):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.Algorithm AS algorithm, 0 AS lic, CreatedBy AS createdby"
        " FROM Application a"
        " WHERE a.AppCode = %s",
        (appcode,),
    )
    app = cur.fetchone()

    if app:
        return app


@bp.route("/<appcode>/update", methods=("GET", "POST"))
@forwarded
@authenticated
def update(appcode):
    app = get_post(appcode)

    if request.method == "POST":
        algorithm = request.form["algorithm"]
        createdby = request.form["createdby"]
        signaturekey = request.form["signkey"]
        privatekey = request.form["privkey"]
        error = None

        if error is not None:
            flash(error)
        else:
            db = get_db()
            cur = db.cursor()
            if signaturekey != "" and privatekey != "":
                crypto.load_privkey(signaturekey.encode("ascii"))
                crypto.load_privkey(privatekey.encode("ascii"))

                cur.execute(
                    "UPDATE Application SET SignatureKey = %s, PrivateKey = %s, Algorithm = %s, CreatedBy = %s"
                    " WHERE AppCode = %s",
                    (signaturekey, privatekey, algorithm, createdby, appcode),
                )
            else:
                cur.execute(
                    "UPDATE Application SET Algorithm = %s, CreatedBy = %s"
                    " WHERE AppCode = %s",
                    (algorithm, createdby, appcode),
                )
            db.commit()

            return redirect(g.request_uri + url_for("index"))

    return render_template("update.html", app=app)


@bp.route("/<appcode>/delete", methods=("POST",))
@forwarded
def delete(appcode):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM Application WHERE AppCode = %s", (appcode,))
    db.commit()
    return redirect(g.request_uri + url_for("index"))


@bp.route("/<appcode>/key")
def key(appcode):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.SignatureKey AS signkey, a.PrivateKey AS privkey, a.Algorithm AS algorithm, 0 AS lic"
        " FROM Application a"
        " WHERE a.AppCode = %s",
        (appcode,),
    )
    app = cur.fetchone()

    if app:
        signkey = crypto.load_privkey(app["signkey"].encode("ascii"))
        privkey = crypto.load_privkey(app["privkey"].encode("ascii"))
        lickey = signkey.public_key()
        pubkey = privkey.public_key()

        cur.execute(
            "SELECT l.CreatedDtm AS createdat, l.Content AS content, l.CreatedBy AS createdby"
            " FROM License l"
            " WHERE l.AppCode = %s"
            " ORDER BY l.CreatedDtm DESC",
            (appcode,),
        )
        app["lics"] = cur.fetchall()

        return render_template(
            "detail_key.html",
            app=app,
            lickey=crypto.export_pubkey(lickey).decode("ascii"),
            pubkey=crypto.export_pubkey(pubkey).decode("ascii"),
        )

    return "Not found", 404


@bp.route("/<appcode>/lic", methods=("GET", "POST"))
@forwarded
@authenticated
def lic(appcode):
    if request.method == "POST":
        content = request.form["content"]
        content = content.replace("\r", "")
        createdby = request.form["createdby"]
        createdat = datetime.now()

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO License (AppCode, CreatedDtm, Content, CreatedBy)"
            " VALUES (%s, %s, %s, %s)",
            (appcode, createdat, content, createdby),
        )
        db.commit()

        return redirect(g.request_uri + url_for("app.lic", appcode=appcode))

    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.SignatureKey AS signkey, a.PrivateKey AS privkey, a.Algorithm AS algorithm, 0 AS lic"
        " FROM Application a"
        " WHERE a.AppCode = %s",
        (appcode,),
    )
    app = cur.fetchone()

    if app:
        signkey = crypto.load_privkey(app["signkey"].encode("ascii"))
        lickey = signkey.public_key()
        lickeystr = crypto.export_pubkey(lickey).decode("ascii")

        cur.execute(
            "SELECT l.CreatedDtm AS createdat, l.Content AS content, l.CreatedBy AS createdby"
            " FROM License l"
            " WHERE l.AppCode = %s"
            " ORDER BY l.CreatedDtm DESC",
            (appcode,),
        )
        app["lics"] = cur.fetchall()

        for l in app["lics"]:
            payload = licmodule.decode(l["content"], lickeystr, app["algorithm"])
            l["payload"] = json.dumps(payload, indent=4)

        return render_template(
            "detail_lic.html",
            uri=g.request_uri,
            app=app,
        )

    return "Not found", 404


@bp.route("/<appcode>/end")
@forwarded
def end(appcode):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.SignatureKey AS signkey, a.PrivateKey AS privkey, a.Algorithm AS algorithm, 0 AS lic"
        " FROM Application a"
        " WHERE a.AppCode = %s",
        (appcode,),
    )
    app = cur.fetchone()

    if app:
        return render_template(
            "detail_end.html",
            uri=g.request_uri,
            app=app,
        )

    return "Not found", 404


@bp.route("/<appcode>/lic/generate", methods=("POST",))
def generate_lic(appcode):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.SignatureKey AS signkey, a.PrivateKey AS privkey,  a.Algorithm AS algorithm, 0 AS lic"
        " FROM Application a"
        " WHERE a.AppCode = %s",
        (appcode,),
    )
    app = cur.fetchone()

    if app:
        payload = json.loads(request.form["payload"])
        signkey = app["signkey"].encode("ascii")
        algorithm = app["algorithm"]
        license = licmodule.generate(payload, signkey, algorithm)

        return jsonify(
            {
                "license": license.decode("ascii"),
            }
        )

    return (
        jsonify(
            {
                "message": f"Application ({appcode}) could not be found",
            }
        ),
        404,
    )


@bp.route("/<appcode>/deletelic", methods=("POST",))
@forwarded
def deletelic(appcode):
    db = get_db()
    cur = db.cursor()
    createdat = request.form["createdat"]
    cur.execute(
        "DELETE FROM License WHERE AppCode = %s and CreatedDtm= %s",
        (appcode, createdat),
    )
    db.commit()
    return redirect(g.request_uri + url_for("app.lic", appcode=appcode))


@bp.route("/<appcode>/encrypt", methods=("POST",))
def encrypt(appcode):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.SignatureKey AS signkey, a.PrivateKey AS privkey,  a.Algorithm AS algorithm, 0 AS lic"
        " FROM Application a"
        " WHERE a.AppCode = %s",
        (appcode,),
    )
    app = cur.fetchone()

    if app:
        content = request.form["content"].encode("ascii")
        privkey = crypto.load_privkey(app["privkey"].encode("ascii"))
        pubkey = privkey.public_key()

        if app["algorithm"] == "EC256":
            result = crypto.encrypt_ec256(content, pubkey)

        elif app["algorithm"] == "Ed25519":
            result = crypto.encrypt_x25519(content, pubkey)

        else:
            result = b"invalid algorithm"

        return jsonify(
            {
                "result": result.decode("ascii"),
            }
        )

    return (
        jsonify(
            {
                "message": f"Application ({appcode}) could not be found",
            }
        ),
        404,
    )


@bp.route("/<appcode>/decrypt", methods=("POST",))
def decrypt(appcode):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.SignatureKey AS signkey, a.PrivateKey AS privkey,  a.Algorithm AS algorithm, 0 AS lic"
        " FROM Application a"
        " WHERE a.AppCode = %s",
        (appcode,),
    )
    app = cur.fetchone()

    if app:
        content = request.form["content"].encode("ascii")
        privkey = crypto.load_privkey(app["privkey"].encode("ascii"))

        if app["algorithm"] == "EC256":
            result = crypto.decrypt_ec256(content, privkey)

        elif app["algorithm"] == "Ed25519":
            result = crypto.decrypt_x25519(content, privkey)

        else:
            result = b"invalid algorithm"

        return jsonify(
            {
                "result": result.decode("ascii"),
            }
        )

    return (
        jsonify(
            {
                "message": f"Application ({appcode}) could not be found",
            }
        ),
        404,
    )
