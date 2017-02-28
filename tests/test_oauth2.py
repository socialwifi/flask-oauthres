# -*- coding: utf-8 -*-
import unittest
from http import HTTPStatus

import flask
import werkzeug
from mock import patch, MagicMock
from requests import Response

from flask_oauthres.oauth2 import OAuth2RemoteTokenService, OAuth2ResourceException
from tests._app import app, oauth
from tests._config import OAUTH2_RESOURCE_ID

RESOURCE_ID = "resource_id"
CLIENT_ID = "client_id"
CLIENT_SECRET = 'client_secret'
CHECK_TOKEN_ENDPOINT_URL = "http://example.com/oauth/check_token"
ACCESS_TOKEN = "123"


class OAuth2RemoteTokenServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.service = OAuth2RemoteTokenService(
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
        with self.assertRaises(OAuth2ResourceException):
            self.service.check_token(None)
        with self.assertRaises(OAuth2ResourceException):
            self.service.check_token("")

    @patch('requests.post')
    def test_check_token_returns_none_if_remote_token_service_is_down(self, mock_post):
        r = Response()
        r.status_code = 500
        mock_post.return_value = r
        with self.assertRaises(OAuth2ResourceException):
            self.service.check_token(ACCESS_TOKEN)

    @patch('requests.post')
    def test_check_token_returns_valid_data_from_remote_token_service(self, mock_post):
        data = {
            'access_token': ACCESS_TOKEN,
            'resources': ['x', 'y'],
            'scope': 'a,b,c'
        }
        r = Response()
        r.status_code = 200
        r.json = lambda: data
        mock_post.return_value = r
        self.assertEqual(self.service.check_token(ACCESS_TOKEN), data)


class OAuth2ResourceTestCase(unittest.TestCase):
    def test_service_is_ok(self):
        self.assertIsNotNone(oauth.service)
        self.assertIsInstance(oauth.service, OAuth2RemoteTokenService)

    @patch('tests._app.oauth.service.check_token')
    def test_verify_request_with_token_as_get_param_and_expect_ok(self, mock_check_token):
        request = MagicMock(
            oauth=None,
            values={'token': ACCESS_TOKEN}
        )
        mock_check_token.return_value = {'access_token': ACCESS_TOKEN, 'resources': [OAUTH2_RESOURCE_ID]}
        oauth.verify_request(request)

    @patch('tests._app.oauth.service.check_token')
    def test_verify_request_with_token_as_http_header_and_expect_ok(self, mock_check_token):
        request = MagicMock(
            oauth=None,
            headers={'Authorization': 'Bearer %s' % ACCESS_TOKEN}
        )
        mock_check_token.return_value = {'access_token': ACCESS_TOKEN, 'resources': [OAUTH2_RESOURCE_ID]}
        oauth.verify_request(request)

    @patch('tests._app.oauth.service.check_token')
    def test_verify_request_and_expect_that_access_to_resource_is_forbidden(self, mock_check_token):
        request = MagicMock(
            oauth=None,
            values={'token': ACCESS_TOKEN}
        )
        mock_check_token.return_value = {'access_token': ACCESS_TOKEN, 'resources': ['fake']}
        with self.assertRaises(werkzeug.exceptions.Unauthorized):
            oauth.verify_request(request)

    @patch('tests._app.oauth.service.check_token')
    def test_verify_request_with_scopes_and_expect_access_granted(self, mock_check_token):
        request = MagicMock(
            oauth=None,
            values={'token': ACCESS_TOKEN}
        )
        mock_check_token.return_value = {
            'access_token': ACCESS_TOKEN,
            'resources': [OAUTH2_RESOURCE_ID],
            'scopes': 'a b c'
        }
        oauth.verify_request(request, scopes=['a', 'b', 'c'])

    @patch('tests._app.oauth.service.check_token')
    def test_verify_request_with_scopes_and_expect_access_forbiden(self, mock_check_token):
        request = MagicMock(
            oauth=None,
            values={'token': ACCESS_TOKEN}
        )
        mock_check_token.return_value = {
            'access_token': ACCESS_TOKEN,
            'resources': [OAUTH2_RESOURCE_ID],
            'scopes': 'a b c'
        }
        with self.assertRaises(werkzeug.exceptions.Unauthorized):
            oauth.verify_request(request, scopes=['a', 'b', 'd'])

    @patch('tests._app.oauth.service.check_token')
    def test_verify_request_with_roles_and_expect_access_granted(self, mock_check_token):
        request = MagicMock(
            oauth=None,
            values={'token': ACCESS_TOKEN}
        )
        mock_check_token.return_value = {
            'access_token': ACCESS_TOKEN,
            'resources': [OAUTH2_RESOURCE_ID],
            'roles': 'ROLE_USER ROLE_ADMIN'
        }
        oauth.verify_request(request, roles=['ROLE_USER', 'ROLE_ADMIN'])

    @patch('tests._app.oauth.service.check_token')
    def test_verify_request_with_roles_and_expect_access_forbiden(self, mock_check_token):
        request = MagicMock(
            oauth=None,
            values={'token': ACCESS_TOKEN}
        )
        mock_check_token.return_value = {
            'access_token': ACCESS_TOKEN,
            'resources': [OAUTH2_RESOURCE_ID],
            'roles': 'ROLE_USER'
        }
        with self.assertRaises(werkzeug.exceptions.Unauthorized):
            oauth.verify_request(request, roles=['ROLE_USER', 'ROLE_ADMIN'])


class FlaskOAuthResIntegrationTestCase(unittest.TestCase):
    def test_not_secured_endpoint_and_expect_status_ok(self):
        with app.test_client() as c:
            r = c.get('/')
            self.assertEqual(r.status_code, HTTPStatus.OK)
            self.assertEqual(flask.request.path, '/')

    def test_secured_endpoint_but_without_token_and_expect_status_badrequest(self):
        with app.test_client() as c:
            r = c.get('/secured_with_scope')
            self.assertEqual(r.status_code, HTTPStatus.BAD_REQUEST)

    @patch('tests._app.oauth.service')
    def test_secured_endpoint_returns_status_unauthorized_when_incorrect_scopes(self, mock_service):
        mock_service.check_token.return_value = {
            'token': ACCESS_TOKEN,
            'resources': [OAUTH2_RESOURCE_ID],
            'scopes': 'a b c'
        }
        mock_service.resource_id = OAUTH2_RESOURCE_ID
        with app.test_client() as c:
            r = c.get('/secured_with_scope', data={'token': ACCESS_TOKEN})
            self.assertEqual(r.status_code, HTTPStatus.UNAUTHORIZED)

    @patch('tests._app.oauth.service')
    def test_secured_endpoint_returns_status_ok_when_correct_scopes(self, mock_service):
        mock_service.check_token.return_value = {
            'token': ACCESS_TOKEN,
            'resources': [OAUTH2_RESOURCE_ID],
            'scopes': 'a b c scope_xyz'
        }
        mock_service.resource_id = OAUTH2_RESOURCE_ID
        with app.test_client() as c:
            r = c.get('/secured_with_scope', data={'token': ACCESS_TOKEN})
            self.assertEqual(r.status_code, HTTPStatus.OK)

    @patch('tests._app.oauth.service')
    def test_secured_endpoint_returns_status_unauthorized_when_incorrect_roles(self, mock_service):
        mock_service.check_token.return_value = {
            'token': ACCESS_TOKEN,
            'resources': [OAUTH2_RESOURCE_ID],
            'roles': 'a b c'
        }
        mock_service.resource_id = OAUTH2_RESOURCE_ID
        with app.test_client() as c:
            r = c.get('/secured_with_role', data={'token': ACCESS_TOKEN})
            self.assertEqual(r.status_code, HTTPStatus.UNAUTHORIZED)

    @patch('tests._app.oauth.service')
    def test_secured_endpoint_returns_status_ok_when_correct_roles(self, mock_service):
        mock_service.check_token.return_value = {
            'token': ACCESS_TOKEN,
            'resources': [OAUTH2_RESOURCE_ID],
            'roles': 'a b c role_xyz'
        }
        mock_service.resource_id = OAUTH2_RESOURCE_ID
        with app.test_client() as c:
            r = c.get('/secured_with_role', data={'token': ACCESS_TOKEN})
            self.assertEqual(r.status_code, HTTPStatus.OK)

if __name__ == '__main__':
    unittest.main()
