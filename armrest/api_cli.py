# -*- coding: utf-8 -*-

import argparse
import logging
import os

from six import text_type
from six.moves.configparser import SafeConfigParser, DEFAULTSECT
from six.moves.urllib.parse import urlparse

from .utils.mime_extension import MimetypeExtension

from .resource_api import AuthMethods, ResourceApi


__all__ = (
    'ApiCli',
    'unicode_as_utf8',
)


class ApiCli(object):
    ApiClass = None

    RequestArgs = ()
    RequestMultiArgs = ()
    SubparserCommandName = '?'
    IdName = 'id'
    IdMetavarName = 'id'
    SecondaryIdName = 'secondary_id'
    Description = None
    Help = None

    Defaults = dict(
        verbose=False,
        dry_run=False,
        raise_on_error=True,
        auth=None,
        auth_method=ResourceApi.AuthMethod,
        output=None,
        content_type=MimetypeExtension.Json,
        headers=None,
        verify_ssl_certs=True,
        timeout=None,
        debug=None,
    )

    @classmethod
    def make(cls, namespace, api_cls=None, base_url_attr='base_url', **kwargs):
        """Factory that creates an ApiClass instance from an Argparse namespace."""
        p = lambda k: (kwargs.pop(k) if kwargs.get(k, None) is not None
                       else getattr(namespace, k, cls.Defaults.get(k, None)))

        kwargs2 = {k: p(k) for k in cls.Defaults}
        kwargs2['url_or_attr'] = p(base_url_attr)
        kwargs2.update(**kwargs)  # Add any unpopped kwargs
        api_cls = api_cls or cls.ApiClass
        return api_cls.make(**kwargs2)

    @classmethod
    def argument_parser(cls, description=None):
        """:rtype: argparse.ArgumentParser"""
        parser = cls.argparse_create(
            description or cls.ApiClass.Description)

        parser.add_argument(
            '--version', action='version',
            version=cls.ApiClass.Version,
            help="Show program's version number and exit")
        parser.add_argument(
            '--dry-run', '-n',
            action='store_true', default=False,
            help="Show what would be generated, but don't make any HTTP requests.")

        cls.argparse_common_args(parser)
        cls.argparse_content_types(parser)
        cls.argparse_auth_args(parser)
        cls.argparse_base_url(parser)
        cls.argparse_input_output(parser)

        return parser

    @classmethod
    def argparse_create(cls, description, **parser_defaults):
        """Create a suitably initialized argument parser.

        :rtype: argparse.ArgumentParser"""
        parser = argparse.ArgumentParser(description=description)
        defaults = cls.Defaults.copy()
        cls.auth_defaults(defaults)
        defaults.update(parser_defaults)
        parser.set_defaults(**defaults)
        return parser

    @classmethod
    def argparse_common_args(cls, parser, **kwargs):
        cls.argparse_simple_args(parser, **kwargs)
        parser.add_argument(
            '--timeout', '-t',
            type=float, default=kwargs.get('timeout', cls.ApiClass.Timeout),
            help="How long to wait for the server to send data before giving up. "
                 "Default: %(default)s seconds.")
        parser.add_argument(
            '--no-verify-ssl-certs', '-V',
            action='store_false', dest='verify_ssl_certs',
            help="Do not verify SSL certs")

    @classmethod
    def argparse_content_types(cls, parser):
        content_type_group = parser.add_argument_group("Content Type")
        content_type_group = content_type_group.add_mutually_exclusive_group()
        content_type_group.add_argument(
            '--json', '-j', dest='content_type',
            action='store_const', const=MimetypeExtension.Json,
            help="Use '%(const)s' for request and response Content-Type.")
        content_type_group.add_argument(
            '--xml', dest='content_type',
            action='store_const', const=MimetypeExtension.Xml,
            help="Use '%(const)s' for request and response Content-Type.")
        return content_type_group

    @classmethod
    def argparse_simple_args(cls, parser, verbose=False, raise_on_error=True, **kwargs):
        parser.add_argument(
            '--verbose', '-v',
            action='store_true', default=verbose,
            help="Be more verbose")
        error_group = parser.add_mutually_exclusive_group()
        error_group.add_argument(
            '--raise-on-error', '-x', dest='raise_on_error',
            action='store_true', default=raise_on_error,
            help="Raise an error for HTTP status codes >= 400. Default: %(default)r")
        error_group.add_argument(
            '--no-raise-on-error', '-X', dest='raise_on_error',
            action='store_false',
            help="Do not raise an error for HTTP status codes >= 400")
        parser.add_argument(
            '--debug', '-d', action='store_true',
            help="Extra debugging information")

    @classmethod
    def argparse_auth_args(cls, parser):
        # TODO: this isn't general enough for OAuth, AWS auth, etc.
        auth_password = parser.get_default('auth_password')
        if auth_password:
            auth_password = auth_password[:2] + ".." + auth_password[-2:]
        auth_group = parser.add_argument_group(
            "Authentication and Authorization",
            description=r"""
Most APIs require a Token for AuthN and AuthZ.
This Auth Token can be specified by --auth.
Otherwise the Auth Token is obtained by
logging into --base-url with AUTH-EMAIL and AUTH-PASSWORD.
These credentials can be supplied in --auth-email and --auth-password.
If one or both are omitted, the ${0} and ${1} environment variables
are examined. Then, if there's a partial email address but no password,
credentials are searched for in {2}.
""".format(cls.EnvVarEmail, cls.EnvVarPassword, cls.auth_config_files_help()))
        auth_group.add_argument(
            '--auth', '-A', metavar="AUTH-TOKEN",
            help="Specify Authorization Token. Use '-' to send no Auth Token.")
        auth_group.add_argument(
            '--auth-email', '-e',
            help="Email address of authentication user. "
                 "Default: {0!r}".format(parser.get_default('auth_email')))
        auth_group.add_argument(
            '--auth-password', '-p',
            help="Password of authentication user. "
                 "Default: {0!r}".format(auth_password))

        auth_method_group = auth_group.add_mutually_exclusive_group()
        auth_method_group.add_argument(
            '--auth-Authorization', '--aa',
            dest='auth_method', action='store_const', const=AuthMethods.AuthorizationHeader,
            help="Use 'Authorization: {0} AUTH-TOKEN' header as auth.{1}".format(
                cls.ApiClass.AuthMethodsClass.AuthorizationName,
                " (Default)" if cls.ApiClass.AuthMethod == AuthMethods.AuthorizationHeader else ""))
        auth_method_group.add_argument(
            '--auth-custom-header', '--ah',
            dest='auth_method', action='store_const', const=AuthMethods.CustomHeader,
            help="Use '{0}: AUTH-TOKEN' header as auth.{1}".format(
                cls.ApiClass.AuthMethodsClass.CustomHeaderName,
                " (Default)" if cls.ApiClass.AuthMethod == AuthMethods.CustomHeader else ""))
        auth_method_group.add_argument(
            '--auth-cookie', '--ac',
            dest='auth_method', action='store_const', const=AuthMethods.Cookie,
            help="Use '{0}=AUTH-TOKEN' cookie as auth.{1}".format(
                cls.ApiClass.AuthMethodsClass.CookieName,
                " (Default)" if cls.ApiClass.AuthMethod == AuthMethods.Cookie else ""))
        auth_method_group.add_argument(
            '--auth-querystring', '--aq',
            dest='auth_method', action='store_const', const=AuthMethods.QueryString,
            help="Use '{0}=AUTH-TOKEN' querystring as auth.{1}".format(
                cls.ApiClass.AuthMethodsClass.QueryStringName,
                " (Default)" if cls.ApiClass.AuthMethod == AuthMethods.QueryString else ""))

    @classmethod
    def argparse_base_url(cls, parser, base_url=None):
        api_cls = cls.ApiClass
        base_url_group = parser.add_argument_group("Server URL")
        base_url_group = base_url_group.add_mutually_exclusive_group()
        base_url_group.add_argument(
            '--base-url', '-B', metavar="BASE-URL",
            nargs="?", default=base_url or 'LocalhostUrl',  # TODO: should this be optional?
            help="Where the server lives. Default: {0!r}.".format(
                api_cls.BaseUrl))
        base_url_group.add_argument(
            '--localhost', '-L',
            dest="base_url", action="store_const", const='LocalhostUrl',
            help="Use localhost ({0!r}) as BASE-URL.".format(
                api_cls.LocalhostUrl))
        return api_cls, base_url_group

    @classmethod
    def argparse_input_output(cls, parser):
        """:type: argparse.ArgumentParser"""
        io_group = parser.add_argument_group("Input/Output")
        # TODO: handle protobuf I/O files too
        # TODO: handle gzipped requests and responses
        io_group.add_argument(
            '--input', '-i',
            help="Read request body from file. Use '-' for stdin.")
        io_group.add_argument(
            '--output', '-o',
            help="Write response body to file. Use '-' for stdout.")

    # Subparser helpers

    @classmethod
    def api_operation(cls, apis, args=None, namespace=None):
        """Parse command line and perform an operation."""
        namespace, parser = cls.parse_args(apis, args, namespace)
        api_cli_cls = namespace.api_cls
        api_cls = api_cli_cls.ApiClass
        if not namespace.operation:
            # Pick longest argument name for each operation
            operations = [
                max(api_cli_cls.OperationMap[operation_id]['args'], key=len)
                for operation_id in api_cls.Operations ]
            parser.error("No operation specified for '{0}'; must be one of {1}".format(
                api_cli_cls.SubparserCommandName, operations))

        cls.init_logging(namespace)
        api_cli_cls.do_auth(namespace)
        api = api_cli_cls.make(namespace, content_type=api_cls.DefaultContentType)
#       api.Logger.debug("%s", namespace)
        kwargs = api_cli_cls.build_operation_args(api, namespace)
#       api.Logger.debug("%s", kwargs)
        operation = getattr(api, namespace.operation)
        response = operation(**kwargs)
        api_cli_cls.handle_response(response, namespace)
        api.Logger.info("%s", response)
        return response

    @classmethod
    def parse_args(cls, apis, args=None, namespace=None):
        """Build argument parser with subparsers for each API, then parse."""
        top_parser = cls.argument_parser()
        subparsers = top_parser.add_subparsers()

        for api in apis:
            api_parser = api.add_subparser(subparsers)
            api.add_subparser_arguments(api_parser)

        namespace = top_parser.parse_args(args, namespace)
        return namespace, top_parser

    @classmethod
    def init_logging(cls, namespace):
        if getattr(namespace, 'output', None) == "-":
            namespace.level = logging.WARNING
        else:
            namespace.level = logging.DEBUG if namespace.verbose else logging.INFO
        api_cls = getattr(namespace, 'api_cls', cls).ApiClass
        namespace.logger = api_cls.init_logging(namespace.level)

    @classmethod
    def do_auth(cls, namespace, **kwargs):
        """Get auth token somehow. Override in derived classes."""
        return namespace.auth

    @classmethod
    def base_url(cls, namespace, base_url_attr=None):
        return getattr(namespace, base_url_attr or 'base_url')

    @classmethod
    def get_auth_email_password(cls, namespace, api_cls, base_url_attr=None):

        def try_auth(email, password, hostname, namespace, handler, filenames):
            if not (email and password):
                for filename in filenames:
                    (email, password) = handler(
                        email, password, hostname, namespace, filename)
                    if email and password:
                        namespace.logger.info(
                            "Using %s credentials <%s> %s..%s",
                            handler.__name__, email, password[:2], password[-2:])
                        break
            return (email, password)

        base_url = api_cls.url_from_attr(cls.base_url(namespace, base_url_attr))
        hostname = urlparse(base_url).hostname

        # search for email address and password in command-line args
        (email, password) = cls.auth_namespace(hostname, namespace)

        # ditto environment variables
        (email, password) = try_auth(
            email, password, hostname, namespace, cls.auth_env_vars, [1])

        if not email:
            raise Exception('Please provide an email address/password pair via command line '
                            'OR an email address/password pair via environment variables '
                            'OR a partial email address via command line matching an appropriate config file entry.')

        # search config file given an (partial) email address
        (email, password) = try_auth(
            email, password, hostname, namespace, cls.auth_config,
            cls.auth_config_files(namespace))

        if not password:
            raise Exception('Credentials not found for hostname "{}" that match partial email address "{}".'.format(
                hostname, email))
        return email, password

    @classmethod
    def auth_defaults(cls, defaults):
        defaults['auth_method'] = cls.Defaults['auth_method']
        if cls.EnvVarEmail:
            defaults['auth_email'] = os.getenv(cls.EnvVarEmail)
        if cls.EnvVarPassword:
            defaults['auth_password'] = os.getenv(cls.EnvVarPassword)

    @classmethod
    def auth_namespace(cls, hostname, namespace):
        return (namespace.auth_email, namespace.auth_password)

    EnvVarEmail = None
    EnvVarPassword = None

    @classmethod
    def auth_env_vars(
            cls, email, password, hostname, namespace, filename,
            envvar_email=None, envvar_password=None):
        envvar_email = envvar_email or cls.EnvVarEmail
        envvar_password = envvar_password or cls.EnvVarPassword
        return (email or (os.getenv(envvar_email) if envvar_email else None),
                password or (os.getenv(envvar_password) if envvar_password else None))

    @classmethod
    def auth_config_files(cls, namespace):
        return []

    @classmethod
    def auth_config_files_help(cls):
        return "<list of config filenames>"

    @classmethod
    def auth_config(cls, email, password, hostname, namespace, dir_file):
        parser = SafeConfigParser()

        def try_section(section, email, password, filename):
            if parser.has_section(section) or section == DEFAULTSECT:
                # look at options which look like EMAIL@DOMAIN = PASSWORD
                # We might want other per-domain options later
                candidates = [(e,p) for e, p in parser.items(section)
                              if '@' in e and e.startswith(email)]
                if len(candidates) == 1:
                    email, password = candidates[0]
                elif len(candidates) > 1:
                    raise ValueError(
                        "Email prefix <{0}> is ambiguous in [{1}] of '{2}'".format(
                            email, section, filename))
            return (email, password)

        if not email:
            # Do not provide default credentials. It's too dangerous.
            return (None, None)

        dir, file = dir_file
        if dir:
            # TODO: check that file is not world-readable
            filename = os.path.join(dir, file)
            parser.read(filename)
            (email, password) = try_section(hostname, email, password, filename)
            if not (email and password):
                (email, password) = try_section(DEFAULTSECT, email, password, filename)
        return (email, password)

    @classmethod
    def build_operation_args(cls, api, namespace):
        """Build args for get_by_id, put_all, etc."""
        operation = cls.OperationMap[namespace.operation]
        kwargs = {'namespace': namespace}
        if getattr(namespace, 'id', None):
            kwargs[cls.IdName] = namespace.id
        if api.SecondaryIdName:
            kwargs[cls.SecondaryIdName] = namespace.secondary_id
        if operation['body']:
            if namespace.input:
                kwargs['payload_obj'] = cls.read_api_input(api, namespace)
            else:
                kwargs['payload_obj'] = cls.make_request_body(namespace)
        if operation.get('verb', False):
            kwargs['path'] = api.Path  # TODO: provide means to override path on command line
            kwargs['response_class'] = api.ResponseClass
        kwargs.update(api.make_url_params(**namespace.__dict__))
        return kwargs

    @classmethod
    def read_api_input(cls, api, namespace):
        return api.read_json(namespace.input)

    @classmethod
    def make_dict(cls, namespace, request_args=None):
        """Make a Dict from an Argparse namespace."""
        d = namespace.__dict__
        request_args = request_args or cls.RequestArgs
        # Extract only those arguments that were explicitly set in namespace
        return dict(
            (k, d[k]) for k in request_args
            if d.get(k, None) is not None)

    @classmethod
    def make_request_body(cls, namespace, request_cls=None, request_args=None):
        """Make a request body object from an Argparse namespace."""
        return cls.make_dict(namespace, request_args)

    @classmethod
    def handle_response(cls, response, namespace):
        pass

    class IdAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            # Update namespace.operation with a string constant
            setattr(namespace, self.dest, self.const)
            # set namespace.id to passed-in value
            setattr(namespace, 'id', values)

    OperationMap = {
        # CRUD operations
        'create': dict(
            args=('-c', '--create'),
            kwargs=dict(action='store_const',
                        help='Create an object'),
            body=True),
        'get_by_id': dict(
            args=('-r', '--retrieve-by-id'),
            kwargs=dict(action=IdAction,
                        help='Retrieve one object'),
            body=False),
        'get_all': dict(
            args=('-R', '--retrieve-all'),
            kwargs=dict(action='store_const',
                        help='Retrieve all objects'),
            body=False),
        'head_by_id': dict(
            args=('--head-by-id',),
            kwargs=dict(action='store_const',
                        help='Retrieve modified time for one object.'),
            body=False),
        'head_all': dict(
            args=('--head-all',),
            kwargs=dict(action='store_const',
                        help='Retrieve latest modified time for all objects.'),
            body=False),
        'put_by_id': dict(
            args=('-u', '--update'),
            kwargs=dict(action=IdAction,
                        help='Update an object'),
            body=True),
        'patch_by_id': dict(
            args=('--patch-by-id',),
            kwargs=dict(action=IdAction,
                        help='Patch an object'),
            body=True),
        'put_all': dict(
            args=('-U', '--update-all'),
            kwargs=dict(action='store_const',
                        help='Update all objects'),
            body=True),
        'patch_all': dict(
            args=('--patch-all',),
            kwargs=dict(action='store_const',
                        help='Patch all objects'),
            body=True),
        'delete_by_id': dict(
            args=('-d', '--delete'),
            kwargs=dict(action=IdAction,
                        help='Delete an object'),
            body=False),

        # HTTP verbs
        'get': dict(
            args=('--get',),
            kwargs=dict(action='store_const',
                        help='GET one object'),
            body=False, verb=True),
        'head': dict(
            args=('--head',),
            kwargs=dict(action='store_const',
                        help='HEAD one object'),
            body=False, verb=True),
        'post': dict(
            args=('--post',),
            kwargs=dict(action='store_const',
                        help='POST an object'),
            body=True, verb=True),
        'put': dict(
            args=('--put',),
            kwargs=dict(action='store_const',
                        help='PUT an object'),
            body=True, verb=True),
        'patch': dict(
            args=('--patch',),
            kwargs=dict(action='store_const',
                        help='PATCH an object'),
            body=True, verb=True),
        'delete': dict(
            args=('--delete',),
            kwargs=dict(action='store_const',
                        help='DELETE one object'),
            body=False, verb=True),
        # TODO: options
        }

    @classmethod
    def add_subparser(cls, subparsers, **kwargs):
        api_parser = subparsers.add_parser(
            cls.SubparserCommandName, description=cls.Description, help=cls.Help)
        api_parser.set_defaults(api_cls=cls)

        # Whitelisted operations
        if cls.ApiClass.Operations:
            operation_group = api_parser.add_mutually_exclusive_group()
            metavar = cls.metavar_name(cls.IdMetavarName)
            for operation_id in cls.ApiClass.Operations:
                operation = cls.OperationMap[operation_id]
                op_kwargs = operation['kwargs'].copy()
                operation_group.add_argument(
                    *operation['args'],
                    dest='operation', const=operation_id,
                    metavar=op_kwargs.pop('metavar', metavar),
                    **op_kwargs)
            if len(cls.ApiClass.Operations) == 1:
                api_parser.set_defaults(operation=cls.ApiClass.Operations[0])
        return api_parser

    @classmethod
    def add_subparser_arguments(cls, subparser, **kwargs):
        # May be overridden in derived Api classes
        return subparser

    @classmethod
    def add_common_subparser_arguments(cls, subparser, argnames):
        if 'email' in argnames:
            subparser.add_argument(
                '--email', '-E',
                help="Email address of user")
        if 'password' in argnames:
            subparser.add_argument(
                '--password', '-P',
                help="Password of user")
        return subparser

    @classmethod
    def metavar_name(cls, id):
        return id.upper().replace("_", "-")


def unicode_as_utf8(s):
    return text_type(s, 'utf8')
