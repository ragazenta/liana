import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from liana.db import get_db

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
    return "Under construction"


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