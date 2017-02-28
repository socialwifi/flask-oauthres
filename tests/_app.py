from flask import Flask
from flask_oauthres import OAuth2Resource
from . import _config

app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY=_config.SECRET_KEY,
    TESTING=_config.TESTING,
    DEBUG=_config.DEBUG
)
oauth = OAuth2Resource(app=app,
                       resource_id=_config.OAUTH2_RESOURCE_ID,
                       client_id=_config.OAUTH2_CLIENT_ID,
                       client_secret=_config.OAUTH2_CLIENT_SECRET,
                       check_token_endpoint_url=_config.OAUTH2_CHECK_TOKEN_ENDPOINT_URL)


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
