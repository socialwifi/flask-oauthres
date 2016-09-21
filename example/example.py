# -*- coding: utf-8 -*-

import logging
from flask import Flask
from flask_oauthres import OAuth2Resource

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config.from_mapping({
    'OAUTH2_RESOURCE_ID': 'resource_helloworld',
    'OAUTH2_CLIENT_ID': 'helloworld_client',
    'OAUTH2_CLIENT_SECRET': 'helloworld_secret',
    'OAUTH2_CHECK_TOKEN_ENDPOINT_URL': 'https://example.com/oauth/check_token'
})
oauth = OAuth2Resource(app)


@app.route('/')
def index():
    return "Hello World!"


@app.route("/api")
@oauth.has_scope('api')
def api():
    return "API"


@app.route("/admin")
@oauth.has_role('ROLE_ADMIN')
def admin():
    return "Hello ADMIN!"


if __name__ == '__main__':
    app.run(host='localhost', port=8080)
