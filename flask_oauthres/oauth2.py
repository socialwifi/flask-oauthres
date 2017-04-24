import functools
import logging

import flask
import requests
import werkzeug

logger = logging.getLogger(__name__)


class OAuth2Resource:
    state_key = 'oauth2resource'

    def __init__(self, resource_id, client_id, client_secret, check_token_endpoint_url, app=None):
        self.resource_id = resource_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.check_token_endpoint_url = check_token_endpoint_url
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        This callback can be used to initialize an application for the
        oauth resource instance.
        """
        self.app = app
        app.extensions = getattr(app, 'extensions', {})
        app.extensions[self.state_key] = self

    @werkzeug.cached_property
    def service(self):
        return OAuth2RemoteTokenService(
            self.resource_id,
            self.client_id,
            self.client_secret,
            self.check_token_endpoint_url
        )

    def verify_request(self, request, scopes=None, roles=None):
        service = self.service
        if hasattr(request, 'oauth') and request.oauth:
            resp = request.oauth
            token = request.oauth.get('access_token')
        else:
            if 'Authorization' in request.headers:
                token = request.headers.get('Authorization')[7:]
            else:
                token = request.values.get('token', None)

            if not token:
                flask.abort(400)

            try:
                resp = service.check_token(token)
            except OAuth2ResourceException:
                flask.abort(400)

        request.oauth = resp
        if self.service.resource_id:
            resources = resp.get('resources', [])
            if self.service.resource_id not in resources:
                logger.debug("Resource=%s is not allowed for token=%s" % (self.service.resource_id, token))
                flask.abort(401)

        if scopes:
            token_scopes = self._parse_space_separated_values(resp.get('scope', ''))
            for scope in scopes:
                if scope not in token_scopes:
                    logger.debug("Missing scope=%s" % scope)
                    flask.abort(401)

        if roles:
            token_roles = resp.get('roles', [])
            for role in roles:
                if role not in token_roles:
                    logger.debug("Missing role=%s" % role)
                    flask.abort(401)

    def has_access(self):
        """Protect resource without checking roles nor scopes."""
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                self.verify_request(flask.request)
                return f(*args, **kwargs)
            return decorated
        return wrapper

    def has_scope(self, *scopes):
        """Protect resource with specified scopes."""
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                self.verify_request(flask.request, scopes=scopes)
                return f(*args, **kwargs)
            return decorated
        return wrapper

    def has_role(self, *roles):
        """Protect resource with specified user roles."""
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                self.verify_request(flask.request, roles=roles)
                return f(*args, **kwargs)
            return decorated
        return wrapper
    
    def _parse_space_separated_values(self, dumped):
        return list(filter(bool, dumped.split(' ')))


class OAuth2ResourceException(Exception):
    pass


class OAuth2RemoteTokenService:
    def __init__(self, resource_id, client_id, client_secret, check_token_endpoint_url):
        self.resource_id = resource_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.check_token_endpoint_url = check_token_endpoint_url

    def check_token(self, token):
        kwargs = dict()
        kwargs['data'] = {'token': token}
        if self.client_id and self.client_secret:
            kwargs['auth'] = requests.auth.HTTPBasicAuth(self.client_id, self.client_secret)
        resp = requests.post(self.check_token_endpoint_url, **kwargs)
        if resp.status_code != 200:
            raise OAuth2ResourceException
        return resp.json()
