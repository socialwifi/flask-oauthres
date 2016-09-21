import logging
from functools import wraps

import requests
from flask import request, abort

log = logging.getLogger(__name__)


class cached_property:

    def __init__(self, func):
        self.__doc__ = getattr(func, '__doc__')
        self.func = func

    def __get__(self, obj, cls):
        if obj is None:
            return self
        value = obj.__dict__[self.func.__name__] = self.func(obj)
        return value


class OAuth2Resource:

    state_key = 'oauth2resource'

    def __init__(self, app=None):
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
        resource_id = self.app.config.get('OAUTH2_RESOURCE_ID', None)
        client_id = self.app.config.get('OAUTH2_CLIENT_ID', None)
        client_secret = self.app.config.get('OAUTH2_CLIENT_SECRET', None)
        check_token_endpoint_url = self.app.config.get('OAUTH2_CHECK_TOKEN_ENDPOINT_URL', None)
        return OAuth2RemoteTokenService(
            resource_id,
            client_id,
            client_secret,
            check_token_endpoint_url
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
                abort(400)

            try:
                resp = service.check_token(token)
            except OAuth2ResourceException:
                abort(400)

        request.oauth = resp
        if self.service.resource_id:
            resources = resp.get('resources', [])
            if self.service.resource_id not in resources:
                log.debug("Resource=%s is not allowed for token=%s" % (self.service.resource_id, token))
                abort(401)

        if scopes:
            token_scopes = resp.get('scopes', [])
            for scope in scopes:
                if scope not in token_scopes:
                    log.debug("Missing scope=%s" % scope)
                    abort(401)

        if roles:
            token_roles = resp.get('roles', [])
            for role in roles:
                if role not in token_roles:
                    log.debug("Missing role=%s" % role)
                    abort(401)

    def has_access(self):
        """Protect resource without checking roles nor scopes."""
        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                self.verify_request(request)
                return f(*args, **kwargs)
            return decorated
        return wrapper

    def has_scope(self, *scopes):
        """Protect resource with specified scopes."""
        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                self.verify_request(request, scopes=scopes)
                return f(*args, **kwargs)
            return decorated
        return wrapper

    def has_role(self, *roles):
        """Protect resource with specified user roles."""
        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                self.verify_request(request, roles=roles)
                return f(*args, **kwargs)
            return decorated
        return wrapper


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
