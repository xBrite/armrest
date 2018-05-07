# -*- coding: utf-8 -*-

import unittest

import mock
from armrest import ApiResponse, ResourceApi

InitialSelfHeaders = {'Some-Header': 'foo-header-value'}
MockRequestId = 'abc-123-uvw-987'

AutomaticHeaders = {'Accept': 'application/json'}


class RestApiUnitTests(unittest.TestCase):
    def setUp(self):
        self.resource_api = ResourceApi(headers=InitialSelfHeaders)

    def test_init_handles_headers_defaults_to_empty(self):
        resource_api = ResourceApi()
        self.assertEquals({}, resource_api.headers)

    def test_init_handles_headers(self):
        self.assertEquals(InitialSelfHeaders, self.resource_api.headers)

    def test__fetch_handles_self_headers(self):
        method = 'POST'
        url = 'http://some.url/path/file.txt'

        expected_headers = self._create_expected_headers(InitialSelfHeaders)

        self._verify_fetch_uses_expected_headers(method, url, expected_headers)

    def test__fetch_handles_supplied_headers(self):
        method = 'POST'
        url = 'http://some.url/path/file.txt'

        input_headers = {'Another-Header': 'bar-header-value'}
        expected_headers = self._create_expected_headers(input_headers)
        self.resource_api.headers = {}

        self._verify_fetch_uses_expected_headers(method, url, expected_headers, input_headers=input_headers)

    def test__fetch_handles_self_and_supplied_headers(self):
        method = 'POST'
        url = 'http://some.url/path/file.txt'

        input_headers = {'Another-Header': 'bar-header-value'}
        expected_headers = self._create_expected_headers(input_headers)
        expected_headers.update(InitialSelfHeaders)

        self._verify_fetch_uses_expected_headers(method, url, expected_headers, input_headers=input_headers)

    def _verify_fetch_uses_expected_headers(self, method, url, expected_headers, input_headers=None):
        mock_response = self.resource_api._dummy_response(method, url)

        with mock.patch.object(ApiResponse, 'fetch', return_value=mock_response) as mocked_fetch:
            response = self.resource_api._fetch(method, url, None, headers=input_headers)

            mocked_fetch.assert_called_once_with(method, url, params=mock.ANY, data=mock.ANY, headers=expected_headers,
                                                 cookies=mock.ANY, verify=True, timeout=mock.ANY)

            self.assertEquals(mock_response, response)

    @classmethod
    def _create_expected_headers(cls, input_headers):
        expected_headers = AutomaticHeaders.copy()
        expected_headers.update(input_headers)
        return expected_headers