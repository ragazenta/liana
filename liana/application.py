import functools

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from liana.db import get_db
from . import crypto

bp = Blueprint("app", __name__)

# Index


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

    # End Index

    # Create


@bp.route("/create", methods=("GET", "POST"))
def create():
    if request.method == "POST":
        code = request.form["appcode"]
        algorithm = request.form["Algorithm"]
        # PrivateKey = request.form['PrivateKey']
        # SignatureKey = request.form['SignatureKey']
        createdby = request.form["CreatedBy"]
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
            cur = db.cursor(dictionary=True)
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
    aps = cur.fetchone()

    print(aps)

    if aps:
        return aps

        # End Create

        # Update


@bp.route("/<appcode>/update", methods=("GET", "POST"))
def update(appcode):
    aps = get_post(appcode)

    if request.method == "POST":
        # code = request.form["AppCode"]
        algorithm = request.form["Algorithm"]
        # PrivateKey = request.form['PrivateKey']
        # SignatureKey = request.form['SignatureKey']
        createdby = request.form["CreatedBy"]
        error = None

        # if not code:
        # error = "AppCode is required."

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
            cur = db.cursor(dictionary=True)
            cur.execute(
                "UPDATE Application SET SignatureKey = %s, PrivateKey = %s, Algorithm = %s, CreatedBy = %s"
                " WHERE AppCode = %s",
                (signaturekey, privatekey, algorithm, createdby, appcode),
            )
            db.commit()
            return redirect(url_for("index"))

    return render_template("update.html", a=aps)

    # End Update

    # Delete


@bp.route("/<appcode>/delete", methods=("POST",))
def delete(appcode):
    get_post(appcode)
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM Application WHERE AppCode = %s", (appcode,))
    db.commit()
    return redirect(url_for("index"))

    # End Delete


@bp.route("/<appcode>")
def get_app(appcode):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.Algorithm AS algorithm, 0 AS lic"
        " FROM Application a"
        " WHERE a.AppCode = %s",
        (appcode,),
    )
    app = cur.fetchone()
    if app:
        return app["code"]

    return "Not found", 404
