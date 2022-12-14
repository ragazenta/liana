import os
import base64

from flask import Flask


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "secret"),
        DB_USERNAME=os.environ.get("DB_USERNAME", "root"),
        DB_PASSWORD=os.environ.get("DB_PASSWORD", ""),
        DB_HOST=os.environ.get("DB_HOST", "127.0.0.1"),
        DB_PORT=int(os.environ.get("DB_PORT", 3306)),
        DB_NAME=os.environ.get("DB_NAME", "Liana"),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.template_filter("b64encode")
    def b64encode(s):
        return base64.b64encode(s.encode("ascii")).decode("ascii")

    from . import db

    db.init_app(app)

    from . import application

    app.register_blueprint(application.bp)
    app.add_url_rule("/", endpoint="index")

    return app
