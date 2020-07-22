from flask import Flask
from .config import Config
from .extensions import db, mail, migrate, jwt
from .user.controllers import user_api
from .auth.controllers import auth_api
from .product.controllers import product_api


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    jwt.init_app(app)

    app.register_blueprint(user_api)
    app.register_blueprint(auth_api)
    app.register_blueprint(product_api)

    return app