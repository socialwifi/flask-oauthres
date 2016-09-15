from flask import Flask
from flask_oauthres import OAuth2Resource


app = Flask(__name__)
app.config.from_object('_config')
oauth = OAuth2Resource(app)


@app.route('/')
def index():
    return "OK"


@app.route('/secured_with_scope')
@oauth.has_scope('scope_xyz')
def endpoint_secured_by_token_with_scope():
    return "OK"


@app.route('/secured_with_role')
@oauth.has_role('role_xyz')
def endpoint_secured_by_token_with_role():
    return "OK"
