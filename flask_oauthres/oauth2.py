import functools
import logging

import flask
import requests
from werkzeug.utils import cached_property

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

    @cached_property
    def service(self):
        return OAuth2RemoteTokenService(
            self.resource_id,
            self.client_id,
            self.client_secret,
            self.check_token_endpoint_url
        )

    def _verify_request(self, request):
        if hasattr(request, 'oauth') and request.oauth:
            resp = request.oauth
        else:
            token = self._get_token_from_request(request)
            if not token:
                flask.abort(400)
            try:
                resp = self.service.check_token(token)
            except OAuth2ResourceException:
                flask.abort(400)
        request.oauth = resp

    def _get_token_from_request(self, request):
        if 'Authorization' in request.headers:
            token = request.headers.get('Authorization')[7:]
        else:
            token = request.values.get('token', None)
        return token

    def _check_has_access(self, request):
        self._verify_request(request)
        token = request.oauth.get('access_token')
        resp = request.oauth
        if self.service.resource_id:
            resources = resp.get('resources', [])
            if self.service.resource_id not in resources:
                logger.debug("Token=%s has no access to resource=%s" % (token, self.service.resource_id))
                flask.abort(401)

    def _check_has_scopes(self, request, scopes):
        self._verify_request(request)
        resp = request.oauth
        token_scopes = self._parse_space_separated_values(resp.get('scope', ''))
        for scope in scopes:
            if scope not in token_scopes:
                logger.debug("Missing required scope=%s" % scope)
                flask.abort(401)

    def _check_has_any_role(self, request, roles):
        self._verify_request(request)
        resp = request.oauth
        token_roles = resp.get('roles', [])
        for role in roles:
            if role in token_roles:
                return
        logger.debug("Missing any role of %s" % str(roles))
        flask.abort(401)

    def _check_has_all_roles(self, request, roles):
        self._verify_request(request)
        resp = request.oauth
        token_roles = resp.get('roles', [])
        for role in roles:
            if role not in token_roles:
                logger.debug("Missing required role=%s" % role)
                flask.abort(401)

    def has_access(self):
        """Protect resource without checking roles nor scopes."""
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                self._check_has_access(flask.request)
                return f(*args, **kwargs)
            return decorated
        return wrapper

    def has_scope(self, *scopes):
        """Protect resource with specified scopes."""
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                self._check_has_scopes(flask.request, scopes)
                return f(*args, **kwargs)
            return decorated
        return wrapper

    def has_any_role(self, *roles):
        """Protect resource with specified user roles."""
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                self._check_has_any_role(flask.request, roles)
                return f(*args, **kwargs)
            return decorated
        return wrapper

    def has_all_roles(self, *roles):
        """Protect resource with specified user roles."""
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                self._check_has_all_roles(flask.request, roles)
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
