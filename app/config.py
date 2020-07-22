class Config:

    SECRET_KEY = 'W09t6WG2z6lxQc55arRUS1bVDA7ESqCqnqG0PDdMkws='

    SQLALCHEMY_DATABASE_URI = 'sqlite:////home/ly/Documents/Code/PAME/back04/data.sqlite'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False

    MAIL_SERVER = 'smtp.sendgrid.net'
    MAIL_PORT = 587
    MAIL_USERNAME = 'apikey'
    MAIL_PASSWORD = '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'
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False

    JWT_SECRET_KEY = SECRET_KEY