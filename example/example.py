# -*- coding: utf-8 -*-

import logging
from flask import Flask
from flask_oauthres import OAuth2Resource

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

oauth = OAuth2Resource(app=app,
                       resource_id='example_resource',
                       client_id='example_client',
                       client_secret='example_secret',
                       check_token_endpoint_url='https://example.com/oauth/check_token')


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
