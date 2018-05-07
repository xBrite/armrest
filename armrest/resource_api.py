# -*- coding: utf-8 -*-

import codecs
import json
import logging
from timeit import default_timer
import sys
import warnings

import requests
import requests.packages.urllib3.exceptions as url3ex

from six import text_type, PY3
from six.moves.urllib.parse import urljoin, urlencode, quote as url_quote, urlparse

if PY3:
    int64 = int
else:
    int64 = long


from .utils.mime_extension import MimetypeExtension
from .utils.logutils import init_console_logging
from .utils.misc import hexdump
from .utils.context_manager import NullContext


__all__ = (
    'AuthMethods',
    'ApiResponse',
    'ResourceApi',
    'int64',
)


class AuthMethods(object):
    AuthorizationHeader = 1
    CustomHeader = 2
    Cookie = 3
    QueryString = 4

    AuthorizationName = None
    CustomHeaderName = None
    CookieName = None
    QueryStringName = None

    NoAuthValue = '-'

    All = (AuthorizationHeader, CustomHeader, Cookie, QueryString)


class ApiResponse(object):
    def __init__(
            self,
            method,
            url,
            requests_response,
            start_time,
            end_time,
            response_data=None
    ):
        self.method = method  # 'get', 'post', etc
        self.url = url
        self.data = response_data  # decoded response body
        self.response = requests_response
        """:type: requests.Response"""
        self.start_time = start_time
        self.end_time = end_time

    @classmethod
    def fetch(
            cls,
            method,
            url,
            params=None,
            data=None,
            headers=None,
            cookies=None,
            verify=True,
            **kwargs
    ):
        start_time = default_timer()
        handler = getattr(requests, method)
        with (NullContext() if verify else warnings.catch_warnings()):
            if verify is False:
                warnings.simplefilter('ignore', url3ex.InsecureRequestWarning)

            requests_response = handler(
                url=url, params=params, data=data,
                headers=headers, cookies=cookies, verify=verify, **kwargs)
            """:type: requests.Response"""
        end_time = default_timer()
        return cls(
            method, url, requests_response, start_time, end_time)

    @classmethod
    def make_error(cls, exc, method, url):
        return cls(method, url, None, 0, 0, response_data=exc)

    def raise_for_status(self):
        if self.response is not None:
            self.response.raise_for_status()
        else:
            raise ValueError("No response")

    @property
    def status_code(self):
        if self.response is not None:
            return self.response.status_code
        else:
            return None

    @property
    def ok(self):
        if self.response is not None:
            return self.response.ok
        else:
            return None

    @property
    def elapsed(self):
        return self.end_time - self.start_time

    def __repr__(self):
        return "<{0} {1} {2}: data={3} response={4} elapsed={5:4.03f}s>".format(
            self.__class__.__name__,
            self.method.upper(),
            self.url,
            self.data,
            self.response,
            self.elapsed
        )

    # TODO: remove this
    def json_data(self):
        return self.data


class ResourceApi(object):
    ApiResponseClass = ApiResponse
    AuthMethodsClass = AuthMethods

    Version = None
    Description = None

    BaseUrl = None
    LocalhostUrl = None
    ServiceName = None
    Timeout = 60.0
    Debug = None

    LoggerName = None
    Logger = logging.getLogger(LoggerName)

    # Override these in derived class, as needed
    Path = ''
    SecondaryIdName = ''
    RequestClass = None
    ResponseClass = None
    MultiRequestClass = None
    MultiResponseClass = None
    DefaultContentType = MimetypeExtension.Json
    Operations = ()
    AuthRequired = False
    AuthMethod = AuthMethodsClass.Cookie

    InterestingResponseHeaders = set(h.lower() for h in {})

    Defaults = dict(
        base_url=None,
        verbose=False,
        dry_run=False,
        raise_on_error=False,
        auth=None,
    )

    def __init__(
            self,
            base_url=None,
            url_or_attr=None,
            verbose=False,
            dry_run=False,
            raise_on_error=False,
            auth=None,
            auth_method=None,
            output=None,
            content_type=None,
            user_agent=None,
            timeout=None,
            headers=None,
            verify_ssl_certs=True,
            debug=None,
            referer=None,
    ):
        self.base_url = base_url or self.BaseUrl
        self.url_or_attr = url_or_attr or self.base_url
        self.verbose = verbose
        self.dry_run = dry_run
        self.raise_on_error = raise_on_error
        self.auth = auth
        self.auth_method = auth_method or self.AuthMethod
        self.output = output
        self.content_type = content_type or self.DefaultContentType
        self.user_agent = user_agent
        self.timeout = timeout or self.Timeout
        self.headers = headers or {}
        self.verify_ssl_certs = verify_ssl_certs
        self.debug = debug if debug is not None else self.Debug
        self.referer = referer

    @classmethod
    def make(cls, url_or_attr, **kwargs):
        return cls(base_url=cls.url_from_attr(url_or_attr),
                   url_or_attr=url_or_attr,
                   **kwargs)

    @classmethod
    def url_from_attr(cls, url_or_attr):
        # e.g., "LocalhostUrl" or "StageApiUrl" or "https://prod-xyz.example.com"
        return getattr(cls, url_or_attr, url_or_attr)

    # Semantic REST operations

    def get_by_id(self, id, path=None, secondary_id=None, namespace=None, headers=None, **params):
        """Send GET request to retrieve a resource by ID.

        :param id: primary (trailing) ID of resource
        :param str path: path of URL, relative to `self.base_url`
        :param secondary_id: secondary ID of resource, if needed.
        :rtype: ApiResponse
        """
        return self._fetch(
            'get',
            self.url(path, id, secondary_id, **params),
            self.ResponseClass,
            headers=headers)

    def head_by_id(self, id, path=None, secondary_id=None, namespace=None, headers=None, **params):
        """Send HEAD request to retrieve last modified from a resource by ID.

        :param id: primary (trailing) ID of resource
        :param str path: path of URL, relative to `self.base_url`
        :param secondary_id: secondary ID of resource, if needed.
        :rtype: ApiResponse
        """
        return self._fetch(
            'head',
            self.url(path, id, secondary_id, **params),
            response_class=None,
            headers=headers)

    def get_all(self, path=None, secondary_id=None, namespace=None, headers=None, app=None, **params):
        """Send GET request to retrieve all resources.

        :param str path: path of URL, relative to `self.base_url`
        :param secondary_id: secondary ID of resource, if needed.
        :rtype: ApiResponse
        """
        params = params or dict()
        if namespace:
            if namespace.offset is not None:
                params['offset'] = namespace.offset
            if namespace.limit is not None:
                params['limit'] = namespace.limit
        return self._fetch(
            'get',
            self.url(path, None, secondary_id, **params),
            self.MultiResponseClass,
            headers=headers,
            app=app)

    def head_all(self, path=None, secondary_id=None, namespace=None, headers=None, **params):
        """Send HEAD request to retrieve latest last modified of all resources.

        :param str path: path of URL, relative to `self.base_url`
        :param secondary_id: secondary ID of resource, if needed.
        :rtype: ApiResponse
        """
        params = params or dict()
        if namespace:
            if namespace.offset is not None:
                params['offset'] = namespace.offset
            if namespace.limit is not None:
                params['limit'] = namespace.limit
        return self._fetch(
            'head',
            self.url(path, None, secondary_id, **params),
            response_class=None,
            headers=headers)

    def create(self, payload_obj, path=None, secondary_id=None, namespace=None, headers=None, **params):
        """Send POST request to create a resource.

        :param payload_obj: request data
        :param str path: path of URL, relative to `self.base_url`
        :param secondary_id: secondary ID of resource, if needed.
        :rtype: ApiResponse
        """
        return self._fetch(
            'post',
            self.url(path, None, secondary_id, **params),
            self.ResponseClass,
            payload_obj=payload_obj,
            headers=headers)

    def delete_by_id(self, id, path=None, secondary_id=None, namespace=None, headers=None, **params):
        """Send DELETE request to delete a resource by ID.

        :param id: primary (trailing) ID of resource
        :param str path: path of URL, relative to `self.base_url`
        :param secondary_id: secondary ID of resource, if needed.
        :rtype: ApiResponse
        """
        return self._fetch(
            'delete',
            self.url(path, id, secondary_id, **params),
            self.ResponseClass,
            headers=headers)

    def put_by_id(self, id, payload_obj, path=None, secondary_id=None, namespace=None, headers=None, **params):
        """Send PUT request to replace a resource by ID.

        :param id: primary (trailing) ID of resource
        :param payload_obj: request data
        :param str path: path of URL, relative to `self.base_url`
        :param secondary_id: secondary ID of resource, if needed.
        :rtype: ApiResponse
        """
        return self._fetch(
            'put',
            self.url(path, id, secondary_id, **params),
            self.ResponseClass,
            payload_obj=payload_obj,
            headers=headers)

    def put_all(self, payload_obj, path=None, secondary_id=None, namespace=None, headers=None, **params):
        """Send PUT request to replace all resources.

        :param payload_obj: request data
        :param str path: path of URL, relative to `self.base_url`
        :param secondary_id: secondary ID of resource, if needed.
        :rtype: ApiResponse
        """
        return self._fetch(
            'put',
            self.url(path, None, secondary_id, **params),
            self.MultiResponseClass,
            payload_obj=payload_obj,
            headers=headers)

    def patch_by_id(self, id, payload_obj, path=None, secondary_id=None, namespace=None, headers=None, **params):
        """Send PATCH request to modify a resource by ID.

        :param id: primary (trailing) ID of resource
        :param payload_obj: request data
        :param str path: path of URL, relative to `self.base_url`
        :param secondary_id: secondary ID of resource, if needed.
        :rtype: ApiResponse
        """
        return self._fetch(
            'patch',
            self.url(path, id, secondary_id, **params),
            self.ResponseClass,
            payload_obj=payload_obj,
            headers=headers)

    def patch_all(self, payload_obj, path=None, secondary_id=None, namespace=None, headers=None, **params):
        """Send PATCH request to update multiple resources.

        :param payload_obj: request data
        :param str path: path of URL, relative to `self.base_url`
        :param secondary_id: secondary ID of resource, if needed.
        :rtype: ApiResponse
        """
        return self._fetch(
            'patch',
            self.url(path, None, secondary_id, **params),
            self.MultiResponseClass,
            payload_obj=payload_obj,
            headers=headers)

    # Direct verb operations

    def get(self, path, response_class, namespace=None, headers=None, **params):
        """Send GET request to retrieve a resource.

        :param str path: path of URL, relative to `self.base_url`
        :param Message response_class: type of the response
        :rtype: ApiResponse
        """
        return self._fetch(
            'get',
            self.url(path, None, None, **params),
            response_class,
            headers=headers)

    def options(self, path, response_class, namespace=None, headers=None, **params):
        """Send OPTIONS request.

        :param str path: path of URL, relative to `self.base_url`
        :param Message response_class: type of the response
        :rtype: ApiResponse
        """
        return self._fetch(
            'options',
            self.url(path, None, None, **params),
            response_class,
            headers=headers)

    def head(self, path, response_class, namespace=None, headers=None, **params):
        """Send HEAD request.

        :param str path: path of URL, relative to `self.base_url`
        :param Message response_class: type of the response
        :rtype: ApiResponse
        """
        return self._fetch(
            'head',
            self.url(path, None, None, **params),
            response_class,
            headers=headers)

    def post(self, path, payload_obj, response_class, namespace=None, headers=None, **params):
        """Send POST request to create resource or to submit an action.

        :param str path: path of URL, relative to `self.base_url`
        :param payload_obj: request data
        :param Message response_class: type of the response
        :rtype: ApiResponse
        """
        return self._fetch(
            'post',
            self.url(path, None, None, **params),
            response_class,
            payload_obj=payload_obj,
            headers=headers)

    def put(self, path, payload_obj, response_class, namespace=None, headers=None, **params):
        """Send PUT request to replace a resource.

        :param str path: path of URL, relative to `self.base_url`
        :param payload_obj: request data
        :param Message response_class: type of the response
        :rtype: ApiResponse
        """
        return self._fetch(
            'put',
            self.url(path, None, None, **params),
            response_class,
            payload_obj=payload_obj,
            headers=headers)

    def patch(self, path, payload_obj, response_class, namespace=None, headers=None, **params):
        """Send PATCH request to patch a resource.

        :param str path: path of URL, relative to `self.base_url`
        :param payload_obj: request data
        :param Message response_class: type of the response
        :rtype: ApiResponse
        """
        return self._fetch(
            'patch',
            self.url(path, None, None, **params),
            response_class,
            payload_obj=payload_obj,
            headers=headers)

    def delete(self, path, response_class, namespace=None, headers=None, **params):
        """Send DELETE request to delete a resource.

        :param str path: path of URL, relative to `self.base_url`
        :param payload_obj: request data
        :param Message response_class: type of the response
        :rtype: ApiResponse
        """
        return self._fetch(
            'delete',
            self.url(path, None, None, **params),
            response_class,
            headers=headers)

    # Implementation

    def url(self, path, id, secondary_id, suffix='', **params):
        return self.join_url(self.base_url, path or self.Path, id, secondary_id, suffix=suffix, **params)

    @classmethod
    def join_url(cls, base_url, path, id=None, secondary_id=None, suffix='', **params):
        url = urljoin(base_url, cls.format_url_ids(path, id, secondary_id)) + suffix
        params = {k: text_type(v) for k, v in params.items() if v is not None}
        if params:
            return url + '?' + urlencode(params)
        else:
            return url

    @classmethod
    def make_url_params(cls, **kwargs):
        return {}

    @classmethod
    def format_url_ids(cls, path, id, secondary_id):
        if id:
            assert path[-1] == '/', path
            utf8_id = text_type(id).encode('utf-8').replace('/', '')  # TODO: ensure slashes don't get %-decoded in requests
            path += url_quote(utf8_id, safe='')
        return path.format(secondary_id)

    @classmethod
    def init_logging(cls, level=logging.DEBUG):
        return init_console_logging(cls.Logger, level)

    @classmethod
    def namespace_default(cls, value, namespace, attr, default):
        if not value:
            value = getattr(namespace, attr) if namespace else default
        return value

    @classmethod
    def qs_bool_param(cls, value, name, namespace, params, default_value=False, transform=int):
        if value is None:
            value = getattr(namespace, name, default_value)
        if value is not None:
            params[name] = transform(value)
        return params

    @classmethod
    def add_auth(cls, auth_method, auth_token, params, headers, cookies):
        if auth_token != cls.AuthMethodsClass.NoAuthValue:
            if auth_method == cls.AuthMethodsClass.AuthorizationHeader:
                headers = headers or {}
                headers['Authorization'] = cls.authorization_header(auth_token)
            elif auth_method == cls.AuthMethodsClass.CustomHeader:
                headers = headers or {}
                headers[cls.AuthMethodsClass.CustomHeaderName] = auth_token
            elif auth_method == cls.AuthMethodsClass.Cookie:
                cookies = cookies or {}
                cookies[cls.AuthMethodsClass.CookieName] = auth_token
            elif auth_method == cls.AuthMethodsClass.QueryString:
                # params are querystring params
                params = params or {}
                params[cls.AuthMethodsClass.QueryStringName] = auth_token
            else:
                # TODO: OAuth, etc
                raise ValueError("Unknown auth method {0}".format(auth_method))
        return params, headers, cookies

    @classmethod
    def authorization_header(cls, auth):
        return "{0} {1}".format(cls.AuthMethodsClass.AuthorizationName, auth)

    def make_requests_headers(
            self,
            headers,
            user_agent=None,
            payload_obj=None,
            content_type=None,
            accept=None,
            **kwargs
    ):
        combined_headers = self.headers.copy()
        combined_headers.update(headers or dict())
        combined_headers.setdefault('Accept', accept or content_type)
        user_agent = user_agent or self.user_agent
        if user_agent:
            combined_headers.setdefault('User-Agent', self.user_agent)
        if self.referer:
            combined_headers.setdefault('Referer', self.referer)
        if payload_obj:
            combined_headers.setdefault('Content-Type', content_type)
        return combined_headers

    def _fetch(
            self,
            method,
            url,
            response_class,
            payload_obj=None,
            content_type=None,
            accept=None,
            headers=None,
            timeout=None,
            **kwargs
    ):
        """Make a request; capture response.

        :rtype: ApiResponse
        """
        # TODO: add request_body_required validation
        content_type = content_type or self.content_type
        params = cookies = None
        headers = self.make_requests_headers(
            headers,
            payload_obj=payload_obj,
            content_type=content_type,
            accept=accept,
            **kwargs
        )

        if self.auth:
            params, headers, cookies = self.add_auth(
                self.auth_method, self.auth, params, headers, cookies)

        if self.verbose:
            self.Logger.info("%s %s", method.upper(), url)
            # TODO: truncate auth_token to first 8 chars when logging
            self.Logger.info("Request Headers: %s", headers)

        if payload_obj is None:
            data = None
        else:
            data = self._serialize_request_body(payload_obj, content_type)

        if self.dry_run:
            api_response = self._dummy_response(method, url)
        else:
            timeout = timeout or self.timeout
            api_response = None
            try:
                api_response = self.ApiResponseClass.fetch(
                    method,
                    url,
                    params=params,
                    data=data,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    verify=self.verify_ssl_certs
                )
            except requests.RequestException as e:
                if self.raise_on_error:
                    if self.verbose:
                        self.Logger.info(
                            "Request failed: %s",
                            self.error_message(api_response, headers),
                            exc_info=1)
                    raise
                else:
                    return self.ApiResponseClass.make_error(e, method, url)

        if self.raise_on_error:
            if 500 <= api_response.status_code < 600:
                self.Logger.info(
                    "Request failed: %s",
                    self.error_message(api_response, headers))
            api_response.raise_for_status()

        api_response.data, response_content_type = self._decode_response(
            response_class, api_response.response)

        if self.output:
            self.write_output(self.output, api_response.data, response_content_type)

        return api_response

    def error_message(self, api_response, request_headers):
        return "[{}]".format(api_response and api_response.status_code)

    def _dummy_response(self, method, url):
        """Used for --dry-run"""
        class DummyResponse:
            status_code = 200
            content = None
            headers = {}
            def raise_for_status(self):
                pass

        return self.ApiResponseClass(
            method, url, DummyResponse(), 0, 0)

    def deserialize_content(self, response_class, content, content_type, status_code, headers):
        if MimetypeExtension.Json in content_type:
            payload_obj = json.loads(content.decode('utf-8') or u'{}')
            response_content_type = MimetypeExtension.Json
        elif MimetypeExtension.Xml in content_type:
            payload_obj = content or ''  # TODO: return a DOM object?
            response_content_type = MimetypeExtension.Xml
        elif MimetypeExtension.Text in content_type:
            try:
                payload_obj = text_type(content or '', 'utf-8')
            except TypeError:
                payload_obj = text_type(content or '')
            response_content_type = MimetypeExtension.Text
        else:
            payload_obj = content
            response_content_type = None
        return payload_obj, response_content_type

    def serialize_content_payload(self, content, content_type):
        if content_type == MimetypeExtension.Text:
            payload = content.encode('utf-8')
        elif content_type == MimetypeExtension.Xml:
            payload = content.encode('utf-8')  # NOTE: For now, expect a string, not a DOM object
        elif content_type == MimetypeExtension.Json:
            payload = json.dumps(content, indent=4)
        else:
            # TODO: handle form data (multipart or url-encoding)
            payload = content  # raw bytes
        return payload

    def serialize_content_message(self, content, payload, content_type):
        if content_type == MimetypeExtension.Text:
            msg = payload
        elif content_type == MimetypeExtension.Xml:
            msg = payload
        elif content_type == MimetypeExtension.Json:
            msg = text_type(payload)
        else:
            # TODO: handle form data (multipart or url-encoding)
            msg = hexdump(content, 16)
        return msg

    def _serialize_request_body(self, content, content_type):
        payload = self.serialize_content_payload(content, content_type)

        if self.verbose:
            msg = self.serialize_content_message(content, payload, content_type)
            if len(msg) > 1000:
                msg = msg[:900] + " ...  " + msg[-75:]  # For hexdump
            self.Logger.debug(
                u"Request Body: %s\n%s",
                content.__class__.__name__, msg)
        return payload

    def _decode_response(self, response_class, response):
        payload_obj, response_content_type = self.deserialize_content(
            response_class,
            response.content,
            response.headers.get('Content-Type', ''),
            response.status_code,
            response.headers
        )

        if self.verbose:
            header_data = dict((k, v) for k,v in response.headers.items()
                               if k.lower() in self.InterestingResponseHeaders)
            if header_data:
                self.Logger.debug("Response Headers: %s", header_data)
            self.Logger.debug("Response Body: %s", payload_obj)

        return payload_obj, response_content_type

    @classmethod
    def read_file(cls, filename, mode="rb", encoding=None):
        if filename == '-':
            # TODO: handle encoding here
            return sys.stdin
        with codecs.open(filename, mode, encoding) as fp:
            return fp.read()

    @classmethod
    def read_json(cls, filename):
        return json.loads(cls.read_file(filename, encoding='utf-8'))

    @classmethod
    def write_output(cls, filename, data, content_type=None):
        if content_type == MimetypeExtension.Json:
            cls.write_json(filename, data)
        else:
            if filename == '-':
                sys.stdout.write(data)
            else:
                with codecs.open(filename, 'w') as f:
                    f.write(data)

    @classmethod
    def write_json(cls, filename, obj, indent=4):
        def json_dump(fp):
            return json.dump(obj, fp, indent=indent)

        if filename == '-':
            return json_dump(sys.stdout)
        else:
            with open(filename, "w") as fp:
                return json_dump(fp)

    def set_user_agent(self, user_agent):
        self.user_agent = user_agent
