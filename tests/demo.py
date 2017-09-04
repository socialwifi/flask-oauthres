import flask
import flask_oauthres
from . import config

app = flask.Flask(__name__)
app.config.from_mapping(
    SECRET_KEY=config.SECRET_KEY,
    TESTING=config.TESTING,
    DEBUG=config.DEBUG
)
oauth = flask_oauthres.OAuth2Resource(app=app,
                                      resource_id=config.OAUTH2_RESOURCE_ID,
                                      client_id=config.OAUTH2_CLIENT_ID,
                                      client_secret=config.OAUTH2_CLIENT_SECRET,
                                      check_token_endpoint_url=config.OAUTH2_CHECK_TOKEN_ENDPOINT_URL)


@app.route('/')
def index():
    return "OK"


@app.route('/secured_with_scope')
@oauth.has_scope('scope_xyz')
def endpoint_secured_by_token_with_scope():
    return "OK"


@app.route('/secured_with_role')
@oauth.has_all_roles('role_xyz')
def endpoint_secured_by_token_with_role():
    return "OK"
