import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
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
    if request.method == 'POST':
        appcode = request.form['AppCode']
        algorithm = request.form['Algorithm']
        # PrivateKey = request.form['PrivateKey']
        # SignatureKey = request.form['SignatureKey']
        createdby = request.form['CreatedBy']
        error = None

        if not appcode:
            error = 'AppCode is required.'
        
        if algorithm == "EC256":
            signaturekey = crypto.export_privkey(crypto.generate_ec256_privkey())
            privatekey = crypto.export_privkey(crypto.generate_ec256_privkey())
        
        elif algorithm == "Ed25519":
            signaturekey = crypto.export_privkey(crypto.generate_ed25519_privkey())
            privatekey = crypto.export_privkey(crypto.generate_x25519_privkey())

        else:
            error = 'invalid Algorithm '

        if error is not None:
            flash(error)
        else:
            db = get_db()
            cur= db.cursor(dictionary=True)
            cur.execute(
                'INSERT INTO Application (AppCode, SignatureKey, PrivateKey, Algorithm, CreatedBy)'
                ' VALUES (%s, %s, %s, %s, %s)',
                (appcode, signaturekey, privatekey, algorithm, createdby)
            )
            db.commit()
            return redirect(url_for('index'))

    return render_template('create.html')

def get_post():
    cur = get_db().cursor()
    cur.execute(
        "SELECT a.AppCode AS code, a.Algorithm AS algorithm, 0 AS lic"
        " FROM Application a"
        " ORDER BY a.AppCode ASC"
    )
    aps =cur.fetchone()

    if aps:
        return aps

                # End Create

                # Update
        
@bp.route('/update', methods=('GET', 'POST'))
def update():
    app = get_post()

    return render_template('update.html', post=app)


                # End Update        


@bp.route("/<appcode>")
def get_app(appcode):
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT a.AppCode AS code, a.Algorithm AS algorithm, 0 AS lic"
        " FROM Application a"
        " WHERE a.AppCode = %s",
        (appcode,)
    )
    app = cur.fetchone()
    if app:
        return app["code"]

    return "Not found", 404