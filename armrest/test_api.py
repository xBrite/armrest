# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import, unicode_literals

import os
import sys
import unittest
import types

from .utils.misc import asbool

from .resource_api import ApiResponse
from .api_cli import ApiCli


__all__ = (
    'explicitly_start',
    'build_nose_args',
    'TestApi',
    'ApiMockMixin',
)


def explicitly_start(function):
    """
    Decorator to run an integration test explicitly, e.g. from PyCharm.
    Breaks slightly when multiple tests are run.
    TODO: Fix how we separate integration tests from lower-level tests.
    """
    def decorator(test_object):
        assert isinstance(function, types.FunctionType), "this decorator is only designed for individual methods"
        assert isinstance(test_object, TestApi)

        previous_value = TestApi.api_config['__explicitly_started']
        TestApi.api_config['__explicitly_started'] = True

        try:
            result = function(test_object)
        except Exception:
            raise
        finally:
            TestApi.api_config['__explicitly_started'] = previous_value

        return result

    return decorator


class TestApi(object):
    """Help tests use ResourceApi and derivatives."""
    ApiCli = ApiCli
    TestApiClass = None

    def __init__(self, api_cls=None, base_url=None, **kwargs):
        self.api = self.make_api(
            api_cls=api_cls or self.TestApiClass,
            base_url=base_url or self.api_config.get('base_url') or (
                self.TestApiClass and self.TestApiClass.LocalhostUrl),
            **kwargs)

    api_config = dict(
        __explicitly_started=False,  # set this to True to run under PyCharm
        base_url=None,
        verbose=False,
        raise_on_error=True,
        auth=None,
        verify_ssl_certs=True,
    )

    @classmethod
    def run_trials(cls, args=None, defaults=None, defaultTest=None, **kwargs):
        # not called run_tests merely because then it would be included in test suite
        namespace = cls.bootstrap(args=args, defaults=defaults)
        return unittest.main(verbosity=2 if namespace.verbose else 1,
                             defaultTest=defaultTest,
                             **kwargs)

    @classmethod
    def explicit_start(cls, **kwargs):
        if kwargs:
            TestApi.api_config.update(kwargs)
        TestApi.api_config['__explicitly_started'] = True

    BootstrapDefaults = None

    @classmethod
    def bootstrap(cls, description=None, args=None, namespace=None, defaults=None):
        """Parse command line, configure ResourceApi"""
        cls.explicit_start()
        namespace = cls.parse_args(
            description, args, namespace,
            defaults if defaults is not None else cls.BootstrapDefaults)
        sys.argv = sys.argv[:1]  # Reset so unittest doesn't reparse
        cls.ApiCli.init_logging(namespace)
        cls.ApiCli.do_auth(
            namespace,
            flight='test.BootstrapAuth',
            verify_ssl_certs=namespace.verify_ssl_certs)
        TestApi.api_config = cls.make_api_config(namespace)  # base class instance
        return namespace

    @classmethod
    def parse_args(
            cls, description=None,
            args=None, namespace=None, defaults=None):
        """Build argument parser, then parse."""
        parser = cls.argument_parser(description, defaults)
        namespace = parser.parse_args(args, namespace)
        return namespace

    @classmethod
    def argument_parser(cls, description=None, defaults=None):
        parser = cls.ApiCli.argparse_create(
            description=description or "Integration Tests",
            **(defaults or {}))
        cls.ApiCli.argparse_common_args(
            parser, verbose=parser.get_default('verbose'))
        cls.ApiCli.argparse_auth_args(parser)
        cls.ApiCli.argparse_base_url(
            parser, base_url=parser.get_default('base_url'))
        cls.argparse_additional(parser)
        return parser

    @classmethod
    def argparse_additional(cls, parser):
        parser.add_argument(
            'start_dir', nargs='?',
            help='Start Directory. Default %(default)r')

    @classmethod
    def make_api(cls, api_cls, api_config=None, base_url=None, **kwargs):
        """Make an instance of `api_cls` using `api_config`."""
        kwargs = cls.make_api_kwargs(api_cls, api_config=api_config, **kwargs)
        url = kwargs.pop('base_url', None)
        base_url = base_url or url
        return api_cls and api_cls.make(base_url, **kwargs)

    @classmethod
    def make_api_config(cls, namespace):
        return dict(
            __explicitly_started=True,
            base_url=namespace.base_url,
            verbose=namespace.verbose,
            raise_on_error=namespace.raise_on_error,
            auth=namespace.auth,
            verify_ssl_certs=namespace.verify_ssl_certs,
        )

    @classmethod
    def make_api_kwargs(
            cls, api_cls, api_config=None, raise_on_error=None,
            verbose=None, auth=None, dry_run=None, **extra):
        """Make an instance of `api_cls` using `api_config`."""
        kwargs = (api_config or cls.api_config).copy()
        kwargs.update(extra)
        # Prevent nosetests inside PyCharm from running these tests
        if not kwargs.pop('__explicitly_started'):
            raise unittest.SkipTest("Not explicitly started")
        if raise_on_error is not None:
            kwargs['raise_on_error'] = raise_on_error
        if verbose is not None:
            kwargs['verbose'] = verbose
        if auth is not None:
            kwargs['auth'] = auth
        if dry_run is not None:
            kwargs['dry_run'] = dry_run
        return kwargs

    # This method's name does not include the word "test" because it causes
    # problems with test discovery
    @classmethod
    def run_integration_t3sts(
            cls,
            start_dir,
            args=None,
            attributes=None,
            negative_attributes=None,
            eval_attr=None,
            xunit_file="nosetests.xml",
            verbose=None,
            base_url="LocalhostUrl",
            reset_sys_argv=False,  # set True if invoked from Fabric or other apps with different arg parsing
            verify_ssl_certs=True,
            **kwargs):
        cls.explicit_start()
        defaults = cls.BootstrapDefaults.copy()
        defaults.update(
            start_dir=start_dir,
            verbose=verbose,
            base_url=base_url,
            verify_ssl_certs=verify_ssl_certs,
        )
        if reset_sys_argv:
            sys.argv[:] = [sys.argv[0]]
        namespace = cls.bootstrap(defaults=defaults, args=args)
        argv = (build_nose_args(attributes=attributes,
                                eval_attr=eval_attr,
                                negative_attributes=negative_attributes,
                                verbose=namespace.verbose,
                                xunit_file=xunit_file,
                                exe=True,
                                argv0=sys.argv[0],
                                **kwargs
                                ) + [start_dir])
        cls.make_os_environ(namespace)

        print("Nose", argv)
        import nose
        nose.main(argv=argv)

    @classmethod
    def make_os_environ(cls, namespace):
        # Override Nose's obnoxious default
        os.environ['NOSE_TESTMATCH'] = '^test_'


class ApiMockMixin(object):
    @classmethod
    def mock_api(cls, api_cls, **method_responses):
        import mock  # Don't want a top-level import

        return mock.patch.object(
            api_cls, 'make',
            return_value=mock.MagicMock(
                **cls._configure_mock_attrs(method_responses)))

    @classmethod
    def _configure_mock_attrs(cls, method_responses):
        """Configure method-response pairs for API.

        For example, dict(create=KeyError, get_by_id=pb_foo_bar, get_all='{"foo": "bar"}')
        becomes
        {
            "create.side_effect": KeyError,
            "get_by_id.return_value": ApiResponse(data=pb_foo_bar),
            "get_all.return_value": ApiResponse(data='{"foo": "bar"}')
        }
        """
        import mock
        attrs = dict()
        for m,r in method_responses.items():
            if mock._is_exception(r) or mock._callable(r):
                k,v = m + '.side_effect', r
            else:
                k,v = m + '.return_value', cls._make_mock_api_response(r)
            attrs[k] = v
        return attrs

    @classmethod
    def _make_mock_api_response(cls, data):
        """Mock ApiResponse.data"""
        api_response = ApiResponse('?', 'url', None, 0, 0)
        api_response.data = data
        return api_response


def build_nose_args(
    parallel=False,
    first_failure_exits=False,
    failed_only=False, with_id=False, verbose=False, detailed_errors=False,
    xunit_file=None, excludes=None, opts=None, process_timeout=120,
    attributes=None,
    negative_attributes=None,
    eval_attr=None,
    exe=None,
    argv0='',
    ):
    """Build command args for nose.main invocation.

    :type dirs: Iterable[str | unicode]
    :type parallel: bool
    :type first_failure_exits: bool
    :type failed_only: bool
    :type with_id: bool
    :type verbose: bool
    :type detailed_errors: bool
    :type xunit_file: str | unicode
    :type excludes: Iterable[str | unicode]
    :type opts: Iterable[str]
    :type process_timeout: int
    :type attributes: Iterable[str | unicode]
    :type negative_attributes: Iterable[str | unicode]
    :type eval_attr: str | unicode
    :type exe: bool
    :type argv0: str | unicode
    """
    argv = opts or []
    argv.insert(0, argv0)  # Nose discards argv[0]
    if asbool(verbose):
        parallel = False  # See https://github.com/nose-devs/nose/issues/441
        argv.append("--verbosity=3")
    else:
        argv.append("--verbosity=2")
    if asbool(with_id):
        parallel = False  # Seems to be a problem too
        argv.append('--with-id')
    if asbool(parallel):
        argv.extend([
            '--processes=-1',
            '--process-timeout={}'.format(process_timeout),
            '--process-restartworker'
        ])
    if xunit_file:
        if parallel:
            argv.extend(["--with-xunitmp", "--xunitmp-file="+xunit_file])
        else:
            argv.extend(["--with-xunit", "--xunit-file="+xunit_file])
    if asbool(first_failure_exits):
        argv.append('--stop')
    if asbool(failed_only):
        argv.append('--failed')
    if asbool(detailed_errors):
        argv.append('--detailed-errors')
    if asbool(exe):
        argv.append('--exe')
    if excludes:
        argv.extend(["--exclude='{0}'".format(e) for e in excludes])
    if attributes:
        for attribute in attributes:
            argv += ["-a", "{}".format(attribute)]
    if negative_attributes:
        for negative_attribute in negative_attributes:
            argv += ["-a", "!{}".format(negative_attribute)]
    if eval_attr:
        argv += ["-A", "{}".format(eval_attr)]
    return argv
