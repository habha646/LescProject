from flask import Flask

from .config import Config
from . import db as db_module


def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    db_module.init_app(app)

    from .routes import dashboard, network, mail_routes, alerts
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(network.bp)
    app.register_blueprint(mail_routes.bp)
    app.register_blueprint(alerts.bp)

    return app
