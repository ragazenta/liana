import mariadb
from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = mariadb.connect(
            user=current_app.config["DB_USERNAME"],
            password=current_app.config["DB_PASSWORD"],
            host=current_app.config["DB_HOST"],
            port=current_app.config["DB_PORT"],
            database=current_app.config["DB_NAME"],
        )

    return g.db


def close_db(e=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_app(app):
    app.teardown_appcontext(close_db)
