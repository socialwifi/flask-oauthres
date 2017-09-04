# -*- coding: utf-8 -*-
import http
import unittest
from unittest import mock

import flask
import werkzeug
import requests

from flask_oauthres import oauth2
from . import demo
from . import config

RESOURCE_ID = "resource_id"
CLIENT_ID = "client_id"
CLIENT_SECRET = 'client_secret'
CHECK_TOKEN_ENDPOINT_URL = "http://example.com/oauth/check_token"
ACCESS_TOKEN = "123"


class OAuth2RemoteTokenServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.service = oauth2.OAuth2RemoteTokenService(
            RESOURCE_ID,
            CLIENT_ID,
            CLIENT_SECRET,
            CHECK_TOKEN_ENDPOINT_URL
        )

    def test_params_are_correct(self):
        self.assertEqual(self.service.resource_id, RESOURCE_ID)
        self.assertEqual(self.service.client_id, CLIENT_ID)
        self.assertEqual(self.service.client_secret, CLIENT_SECRET)
        self.assertEqual(self.service.check_token_endpoint_url, CHECK_TOKEN_ENDPOINT_URL)

    def test_check_token_returns_none_if_token_is_empty(self):
        with self.assertRaises(oauth2.OAuth2ResourceException):
            self.service.check_token(None)
        with self.assertRaises(oauth2.OAuth2ResourceException):
            self.service.check_token("")

    @mock.patch('requests.post')
    def test_check_token_returns_none_if_remote_token_service_is_down(self, mock_post):
        r = requests.Response()
        r.status_code = 500
        mock_post.return_value = r
        with self.assertRaises(oauth2.OAuth2ResourceException):
            self.service.check_token(ACCESS_TOKEN)

    @mock.patch('requests.post')
    def test_check_token_returns_valid_data_from_remote_token_service(self, mock_post):
        data = {
            'access_token': ACCESS_TOKEN,
            'resources': ['x', 'y'],
            'scope': 'a,b,c'
        }
        r = requests.Response()
        r.status_code = 200
        r.json = lambda: data
        mock_post.return_value = r
        self.assertEqual(self.service.check_token(ACCESS_TOKEN), data)


class OAuth2ResourceTestCase(unittest.TestCase):
    def test_service_is_ok(self):
        self.assertIsNotNone(demo.oauth.service)
        self.assertIsInstance(demo.oauth.service, oauth2.OAuth2RemoteTokenService)

    @mock.patch('tests.demo.oauth.service.check_token')
    def test_check_has_access_with_token_as_get_param_and_expect_ok(self, mock_check_token):
        request = mock.MagicMock(
            oauth=None,
            values={'token': ACCESS_TOKEN}
        )
        mock_check_token.return_value = {'access_token': ACCESS_TOKEN, 'resources': [config.OAUTH2_RESOURCE_ID]}
        demo.oauth._check_has_access(request)

    @mock.patch('tests.demo.oauth.service.check_token')
    def test_check_has_access_with_token_as_http_header_and_expect_ok(self, mock_check_token):
        request = mock.MagicMock(
            oauth=None,
            headers={'Authorization': 'Bearer %s' % ACCESS_TOKEN}
        )
        mock_check_token.return_value = {'access_token': ACCESS_TOKEN, 'resources': [config.OAUTH2_RESOURCE_ID]}
        demo.oauth._check_has_access(request)

    @mock.patch('tests.demo.oauth.service.check_token')
    def test_check_has_access_and_expect_that_access_to_resource_is_forbidden(self, mock_check_token):
        request = mock.MagicMock(
            oauth=None,
            values={'token': ACCESS_TOKEN}
        )
        mock_check_token.return_value = {'access_token': ACCESS_TOKEN, 'resources': ['fake']}
        with self.assertRaises(werkzeug.exceptions.Unauthorized):
            demo.oauth._check_has_access(request)

    @mock.patch('tests.demo.oauth.service.check_token')
    def test_check_has_scopes_expect_access_granted(self, mock_check_token):
        request = mock.MagicMock(
            oauth=None,
            values={'token': ACCESS_TOKEN}
        )
        mock_check_token.return_value = {
            'access_token': ACCESS_TOKEN,
            'resources': [config.OAUTH2_RESOURCE_ID],
            'scope': 'a b c'
        }
        demo.oauth._check_has_scopes(request, ['a', 'b', 'c'])

    @mock.patch('tests.demo.oauth.service.check_token')
    def test_check_has_scopes_expect_access_forbiden(self, mock_check_token):
        request = mock.MagicMock(
            oauth=None,
            values={'token': ACCESS_TOKEN}
        )
        mock_check_token.return_value = {
            'access_token': ACCESS_TOKEN,
            'resources': [config.OAUTH2_RESOURCE_ID],
            'scope': 'a b c'
        }
        with self.assertRaises(werkzeug.exceptions.Unauthorized):
            demo.oauth._check_has_scopes(request, ['a', 'b', 'd'])


class FlaskOAuthResIntegrationTestCase(unittest.TestCase):
    def test_not_secured_endpoint_and_expect_status_ok(self):
        with demo.app.test_client() as c:
            r = c.get('/')
            self.assertEqual(r.status_code, http.HTTPStatus.OK)
            self.assertEqual(flask.request.path, '/')

    def test_secured_endpoint_but_without_token_and_expect_status_badrequest(self):
        with demo.app.test_client() as c:
            r = c.get('/secured_with_scope')
            self.assertEqual(r.status_code, http.HTTPStatus.BAD_REQUEST)

    @mock.patch('tests.demo.oauth.service')
    def test_secured_endpoint_with_scope_returns_status_unauthorized_when_incorrect_scopes(self, mock_service):
        mock_service.check_token.return_value = {
            'token': ACCESS_TOKEN,
            'resources': [config.OAUTH2_RESOURCE_ID],
            'scope': 'a b c'
        }
        mock_service.resource_id = config.OAUTH2_RESOURCE_ID
        with demo.app.test_client() as c:
            r = c.get('/secured_with_scope', data={'token': ACCESS_TOKEN})
            self.assertEqual(r.status_code, http.HTTPStatus.UNAUTHORIZED)

    @mock.patch('tests.demo.oauth.service')
    def test_secured_endpoint_with_scope_returns_status_ok_when_correct_scopes(self, mock_service):
        mock_service.check_token.return_value = {
            'token': ACCESS_TOKEN,
            'resources': [config.OAUTH2_RESOURCE_ID],
            'scope': 'a b c scope_xyz'
        }
        mock_service.resource_id = config.OAUTH2_RESOURCE_ID
        with demo.app.test_client() as c:
            r = c.get('/secured_with_scope', data={'token': ACCESS_TOKEN})
            self.assertEqual(r.status_code, http.HTTPStatus.OK)

    @mock.patch('tests.demo.oauth.service')
    def test_secured_endpoint_with_role_returns_status_unauthorized_when_incorrect_roles(self, mock_service):
        mock_service.check_token.return_value = {
            'token': ACCESS_TOKEN,
            'resources': [config.OAUTH2_RESOURCE_ID],
            'roles': 'a b c'
        }
        mock_service.resource_id = config.OAUTH2_RESOURCE_ID
        with demo.app.test_client() as c:
            r = c.get('/secured_with_role', data={'token': ACCESS_TOKEN})
            self.assertEqual(r.status_code, http.HTTPStatus.UNAUTHORIZED)

    @mock.patch('tests.demo.oauth.service')
    def test_secured_endpoint_with_role_returns_status_ok_when_correct_roles(self, mock_service):
        mock_service.check_token.return_value = {
            'token': ACCESS_TOKEN,
            'resources': [config.OAUTH2_RESOURCE_ID],
            'roles': 'a b c role_xyz'
        }
        mock_service.resource_id = config.OAUTH2_RESOURCE_ID
        with demo.app.test_client() as c:
            r = c.get('/secured_with_role', data={'token': ACCESS_TOKEN})
            self.assertEqual(r.status_code, http.HTTPStatus.OK)

if __name__ == '__main__':
    unittest.main()
