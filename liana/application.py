import json
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
from . import crypto, lic

bp = Blueprint("app", __name__)


@bp.route("/")
def index():
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.Algorithm AS algorithm, 0 AS lic"
        " FROM Application a"
        " ORDER BY a.AppCode ASC"
    )
    apps = cur.fetchall()
    return render_template("index.html", apps=apps)


@bp.route("/create", methods=("GET", "POST"))
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
            return redirect(url_for("index"))

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
def update(appcode):
    app = get_post(appcode)

    if request.method == "POST":
        algorithm = request.form["algorithm"]
        createdby = request.form["createdby"]
        error = None

        if algorithm == "EC256":
            signaturekey = crypto.export_privkey(crypto.generate_ec256_privkey())
            privatekey = crypto.export_privkey(crypto.generate_ec256_privkey())

        elif algorithm == "Ed25519":
            signaturekey = crypto.export_privkey(crypto.generate_ed25519_privkey())
            privatekey = crypto.export_privkey(crypto.generate_x25519_privkey())

        else:
            error = "invalid Algorithm"

        if error is not None:
            flash(error)
        else:
            db = get_db()
            cur = db.cursor()
            cur.execute(
                "UPDATE Application SET SignatureKey = %s, PrivateKey = %s, Algorithm = %s, CreatedBy = %s"
                " WHERE AppCode = %s",
                (signaturekey, privatekey, algorithm, createdby, appcode),
            )
            db.commit()
            return redirect(url_for("index"))

    return render_template("update.html", a=app)


@bp.route("/<appcode>/delete", methods=("POST",))
def delete(appcode):
    get_post(appcode)
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM Application WHERE AppCode = %s", (appcode,))
    db.commit()
    return redirect(url_for("index"))


@bp.route("/<appcode>")
def get_app(appcode):
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
            "detail.html",
            app=app,
            lickey=crypto.export_pubkey(lickey).decode("ascii"),
            pubkey=crypto.export_pubkey(pubkey).decode("ascii"),
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
        license = lic.generate(payload, signkey, algorithm)

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


@bp.route("/<appcode>/lic/save", methods=("POST",))
def save_lic(appcode):
    content = request.form["content"]
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

    return jsonify(
        {
            "content": content,
            "createdby": createdby,
            "createdat": createdat,
        }
    )


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
