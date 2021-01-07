# Copyright 2011 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Utility methods for working with WSGI servers
"""
import errno
import socket
import sys
import time

import eventlet.wsgi
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as exception
from oslo_config import cfg
import oslo_i18n
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_service import service as common_service
from oslo_service import sslutils
from oslo_service import systemd
from oslo_service import wsgi
from oslo_utils import encodeutils
from oslo_utils import excutils
import webob.dec
import webob.exc

from neutron._i18n import _
from neutron.common import config
from neutron.conf import wsgi as wsgi_config
from neutron import worker as neutron_worker

CONF = cfg.CONF
wsgi_config.register_socket_opts()

LOG = logging.getLogger(__name__)


def encode_body(body):
    """Encode unicode body.

    WebOb requires to encode unicode body used to update response body.
    """
    return encodeutils.to_utf8(body)


class WorkerService(neutron_worker.NeutronBaseWorker):
    """Wraps a worker to be handled by ProcessLauncher"""
    def __init__(self, service, application, set_proctitle, disable_ssl=False,
                 worker_process_count=0, desc=None):
        super(WorkerService, self).__init__(worker_process_count,
                                            set_proctitle)

        self._service = service
        self._application = application
        self._disable_ssl = disable_ssl
        self._server = None
        self.desc = desc

    def start(self, desc=None):
        desc = desc or self.desc
        super(WorkerService, self).start(desc=desc)
        # When api worker is stopped it kills the eventlet wsgi server which
        # internally closes the wsgi server socket object. This server socket
        # object becomes not usable which leads to "Bad file descriptor"
        # errors on service restart.
        # Duplicate a socket object to keep a file descriptor usable.
        dup_sock = self._service._socket.dup()
        if CONF.use_ssl and not self._disable_ssl:
            dup_sock = sslutils.wrap(CONF, dup_sock)
        self._server = self._service.pool.spawn(self._service._run,
                                                self._application,
                                                dup_sock)

    def wait(self):
        if isinstance(self._server, eventlet.greenthread.GreenThread):
            self._server.wait()

    def stop(self):
        if isinstance(self._server, eventlet.greenthread.GreenThread):
            self._server.kill()
            self._server = None

    @staticmethod
    def reset():
        config.reset_service()


class Server(object):
    """Server class to manage multiple WSGI sockets and applications."""

    def __init__(self, name, num_threads=None, disable_ssl=False):
        # Raise the default from 8192 to accommodate large tokens
        eventlet.wsgi.MAX_HEADER_LINE = CONF.max_header_line
        self.num_threads = num_threads or CONF.wsgi_default_pool_size
        self.disable_ssl = disable_ssl
        # Pool for a greenthread in which wsgi server will be running
        self.pool = eventlet.GreenPool(1)
        self.name = name
        self._server = None
        # A value of 0 is converted to None because None is what causes the
        # wsgi server to wait forever.
        self.client_socket_timeout = CONF.client_socket_timeout or None
        if CONF.use_ssl and not self.disable_ssl:
            sslutils.is_enabled(CONF)

    def _get_socket(self, host, port, backlog):
        bind_addr = (host, port)
        # TODO(dims): eventlet's green dns/socket module does not actually
        # support IPv6 in getaddrinfo(). We need to get around this in the
        # future or monitor upstream for a fix
        try:
            info = socket.getaddrinfo(bind_addr[0],
                                      bind_addr[1],
                                      socket.AF_UNSPEC,
                                      socket.SOCK_STREAM)[0]
            family = info[0]
            bind_addr = info[-1]
        except Exception:
            LOG.exception("Unable to listen on %(host)s:%(port)s",
                          {'host': host, 'port': port})
            sys.exit(1)

        sock = None
        retry_until = time.time() + CONF.retry_until_window
        while not sock and time.time() < retry_until:
            try:
                sock = eventlet.listen(bind_addr,
                                       backlog=backlog,
                                       family=family)
            except socket.error as err:
                with excutils.save_and_reraise_exception() as ctxt:
                    if err.errno == errno.EADDRINUSE:
                        ctxt.reraise = False
                        eventlet.sleep(0.1)
        if not sock:
            raise RuntimeError(_("Could not bind to %(host)s:%(port)s "
                               "after trying for %(time)d seconds") %
                               {'host': host,
                                'port': port,
                                'time': CONF.retry_until_window})
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # sockets can hang around forever without keepalive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        # This option isn't available in the OS X version of eventlet
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP,
                            socket.TCP_KEEPIDLE,
                            CONF.tcp_keepidle)

        return sock

    def start(self, application, port, host='0.0.0.0', workers=0, desc=None):
        """Run a WSGI server with the given application."""
        self._host = host
        self._port = port
        backlog = CONF.backlog

        self._socket = self._get_socket(self._host,
                                        self._port,
                                        backlog=backlog)

        self._launch(application, workers, desc)

    def _launch(self, application, workers=0, desc=None):
        set_proctitle = "off" if desc is None else CONF.setproctitle
        service = WorkerService(self, application, set_proctitle,
                                self.disable_ssl, workers, desc)
        if workers < 1:
            # The API service should run in the current process.
            self._server = service
            # Dump the initial option values
            cfg.CONF.log_opt_values(LOG, logging.DEBUG)
            service.start(desc=desc)
            systemd.notify_once()
        else:
            # dispose the whole pool before os.fork, otherwise there will
            # be shared DB connections in child processes which may cause
            # DB errors.
            db_api.get_context_manager().dispose_pool()
            # The API service runs in a number of child processes.
            # Minimize the cost of checking for child exit by extending the
            # wait interval past the default of 0.01s.
            self._server = common_service.ProcessLauncher(
                cfg.CONF, wait_interval=1.0, restart_method='mutate')
            self._server.launch_service(service,
                                        workers=service.worker_process_count)

    @property
    def host(self):
        return self._socket.getsockname()[0] if self._socket else self._host

    @property
    def port(self):
        return self._socket.getsockname()[1] if self._socket else self._port

    def stop(self):
        self._server.stop()

    def wait(self):
        """Wait until all servers have completed running."""
        try:
            self._server.wait()
        except KeyboardInterrupt:
            pass

    def _run(self, application, socket):
        """Start a WSGI server in a new green thread."""
        eventlet.wsgi.server(socket, application,
                             max_size=self.num_threads,
                             log=LOG,
                             keepalive=CONF.wsgi_keep_alive,
                             log_format=CONF.wsgi_log_format,
                             socket_timeout=self.client_socket_timeout)

    @property
    def process_launcher(self):
        if isinstance(self._server, common_service.ProcessLauncher):
            return self._server
        return None


class Request(wsgi.Request):

    def best_match_content_type(self):
        """Determine the most acceptable content-type.

        Based on:
            1) URI extension (.json)
            2) Content-type header
            3) Accept* headers
        """
        # First lookup http request path
        parts = self.path.rsplit('.', 1)
        if len(parts) > 1:
            _format = parts[1]
            if _format in ['json']:
                return 'application/{0}'.format(_format)

        # Then look up content header
        type_from_header = self.get_content_type()
        if type_from_header:
            return type_from_header
        ctypes = ['application/json']

        # Finally search in Accept-* headers
        acceptable = self.accept.acceptable_offers(ctypes)
        if acceptable:
            return acceptable[0][0]
        return 'application/json'

    def get_content_type(self):
        allowed_types = ("application/json",)
        if "Content-Type" not in self.headers:
            LOG.debug("Missing Content-Type")
            return None
        _type = self.content_type
        if _type in allowed_types:
            return _type
        return None

    def best_match_language(self):
        """Determines best available locale from the Accept-Language header.

        :returns: the best language match or None if the 'Accept-Language'
                  header was not available in the request.
        """
        if not self.accept_language:
            return None
        all_languages = oslo_i18n.get_available_languages('neutron')
        best_match = self.accept_language.lookup(all_languages,
                                                 default='fake_LANG')
        if best_match == 'fake_LANG':
            best_match = None
        return best_match

    @property
    def context(self):
        if 'neutron.context' not in self.environ:
            self.environ['neutron.context'] = context.get_admin_context()
        return self.environ['neutron.context']


class ActionDispatcher(object):
    """Maps method name to local methods through action name."""

    def dispatch(self, *args, **kwargs):
        """Find and call local method."""
        action = kwargs.pop('action', 'default')
        action_method = getattr(self, str(action), self.default)
        return action_method(*args, **kwargs)

    def default(self, data):
        raise NotImplementedError()


class DictSerializer(ActionDispatcher):
    """Default request body serialization."""

    def serialize(self, data, action='default'):
        return self.dispatch(data, action=action)

    def default(self, data):
        return ""


class JSONDictSerializer(DictSerializer):
    """Default JSON request body serialization."""

    def default(self, data):
        def sanitizer(obj):
            return str(obj)
        return encode_body(jsonutils.dumps(data, default=sanitizer))


class ResponseHeaderSerializer(ActionDispatcher):
    """Default response headers serialization."""

    def serialize(self, response, data, action):
        self.dispatch(response, data, action=action)

    def default(self, response, data):
        response.status_int = 200


class ResponseSerializer(object):
    """Encode the necessary pieces into a response object."""

    def __init__(self, body_serializers=None, headers_serializer=None):
        self.body_serializers = {
            'application/json': JSONDictSerializer(),
        }
        self.body_serializers.update(body_serializers or {})

        self.headers_serializer = (headers_serializer or
                                   ResponseHeaderSerializer())

    def serialize(self, response_data, content_type, action='default'):
        """Serialize a dict into a string and wrap in a wsgi.Request object.

        :param response_data: dict produced by the Controller
        :param content_type: expected mimetype of serialized response body

        """
        response = webob.Response()
        self.serialize_headers(response, response_data, action)
        self.serialize_body(response, response_data, content_type, action)
        return response

    def serialize_headers(self, response, data, action):
        self.headers_serializer.serialize(response, data, action)

    def serialize_body(self, response, data, content_type, action):
        response.headers['Content-Type'] = content_type
        if data is not None:
            serializer = self.get_body_serializer(content_type)
            response.body = serializer.serialize(data, action)

    def get_body_serializer(self, content_type):
        try:
            return self.body_serializers[content_type]
        except (KeyError, TypeError):
            raise exception.InvalidContentType(content_type=content_type)


class TextDeserializer(ActionDispatcher):
    """Default request body deserialization."""

    def deserialize(self, datastring, action='default'):
        return self.dispatch(datastring, action=action)

    def default(self, datastring):
        return {}


class JSONDeserializer(TextDeserializer):

    def _from_json(self, datastring):
        try:
            return jsonutils.loads(datastring)
        except ValueError:
            msg = _("Cannot understand JSON")
            raise exception.MalformedRequestBody(reason=msg)

    def default(self, datastring):
        return {'body': self._from_json(datastring)}


class RequestHeadersDeserializer(ActionDispatcher):
    """Default request headers deserializer."""

    def deserialize(self, request, action):
        return self.dispatch(request, action=action)

    def default(self, request):
        return {}


class RequestDeserializer(object):
    """Break up a Request object into more useful pieces."""

    def __init__(self, body_deserializers=None, headers_deserializer=None):
        self.body_deserializers = {
            'application/json': JSONDeserializer(),
        }
        self.body_deserializers.update(body_deserializers or {})

        self.headers_deserializer = (headers_deserializer or
                                     RequestHeadersDeserializer())

    def deserialize(self, request):
        """Extract necessary pieces of the request.

        :param request: Request object
        :returns: tuple of expected controller action name, dictionary of
                 keyword arguments to pass to the controller, the expected
                 content type of the response

        """
        action_args = self.get_action_args(request.environ)
        action = action_args.pop('action', None)

        action_args.update(self.deserialize_headers(request, action))
        action_args.update(self.deserialize_body(request, action))

        accept = self.get_expected_content_type(request)

        return (action, action_args, accept)

    def deserialize_headers(self, request, action):
        return self.headers_deserializer.deserialize(request, action)

    def deserialize_body(self, request, action):
        try:
            content_type = request.best_match_content_type()
        except exception.InvalidContentType:
            LOG.debug("Unrecognized Content-Type provided in request")
            return {}

        if content_type is None:
            LOG.debug("No Content-Type provided in request")
            return {}

        if not len(request.body) > 0:
            LOG.debug("Empty body provided in request")
            return {}

        try:
            deserializer = self.get_body_deserializer(content_type)
        except exception.InvalidContentType:
            with excutils.save_and_reraise_exception():
                LOG.debug("Unable to deserialize body as provided "
                          "Content-Type")

        return deserializer.deserialize(request.body, action)

    def get_body_deserializer(self, content_type):
        try:
            return self.body_deserializers[content_type]
        except (KeyError, TypeError):
            raise exception.InvalidContentType(content_type=content_type)

    def get_expected_content_type(self, request):
        return request.best_match_content_type()

    def get_action_args(self, request_environment):
        """Parse dictionary created by routes library."""
        try:
            args = request_environment['wsgiorg.routing_args'][1].copy()
        except Exception:
            return {}

        try:
            del args['controller']
        except KeyError:
            pass

        try:
            del args['format']
        except KeyError:
            pass

        return args


class Application(object):
    """Base WSGI application wrapper. Subclasses need to implement __call__."""

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for paste app factories in paste.deploy config files.

        Any local configuration (that is, values under the [app:APPNAME]
        section of the paste config) will be passed into the `__init__` method
        as kwargs.

        A hypothetical configuration would look like:

            [app:wadl]
            latest_version = 1.3
            paste.app_factory = nova.api.fancy_api:Wadl.factory

        which would result in a call to the `Wadl` class as

            import neutron.api.fancy_api
            fancy_api.Wadl(latest_version='1.3')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        return cls(**local_config)

    def __call__(self, environ, start_response):
        r"""Subclasses will probably want to implement __call__ like this:

        @webob.dec.wsgify(RequestClass=Request)
        def __call__(self, req):
          # Any of the following objects work as responses:

          # Option 1: simple string
          res = 'message\n'

          # Option 2: a nicely formatted HTTP exception page
          res = exc.HTTPForbidden(explanation='Nice try')

          # Option 3: a webob Response object (in case you need to play with
          # headers, or you want to be treated like an iterable, or or or)
          res = Response();
          res.app_iter = open('somefile')

          # Option 4: any wsgi app to be run next
          res = self.application

          # Option 5: you can get a Response object for a wsgi app, too, to
          # play with headers etc
          res = req.get_response(self.application)

          # You can then just return your response...
          return res
          # ... or set req.response and return None.
          req.response = res

        See the end of http://pythonpaste.org/webob/modules/dec.html
        for more info.

        """
        raise NotImplementedError(_('You must implement __call__'))


class Resource(Application):
    """WSGI app that handles (de)serialization and controller dispatch.

    WSGI app that reads routing information supplied by RoutesMiddleware
    and calls the requested action method upon its controller.  All
    controller action methods must accept a 'req' argument, which is the
    incoming wsgi.Request. If the operation is a PUT or POST, the controller
    method must also accept a 'body' argument (the deserialized request body).
    They may raise a webob.exc exception or return a dict, which will be
    serialized by requested content type.

    """

    def __init__(self, controller, fault_body_function,
                 deserializer=None, serializer=None):
        """Object initialization.

        :param controller: object that implement methods created by routes lib
        :param deserializer: object that can serialize the output of a
                             controller into a webob response
        :param serializer: object that can deserialize a webob request
                           into necessary pieces
        :param fault_body_function: a function that will build the response
                                    body for HTTP errors raised by operations
                                    on this resource object

        """
        self.controller = controller
        self.deserializer = deserializer or RequestDeserializer()
        self.serializer = serializer or ResponseSerializer()
        self._fault_body_function = fault_body_function

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, request):
        """WSGI method that controls (de)serialization and method dispatch."""

        LOG.info("%(method)s %(url)s",
                 {"method": request.method, "url": request.url})

        try:
            action, args, accept = self.deserializer.deserialize(request)
        except exception.InvalidContentType:
            msg = _("Unsupported Content-Type")
            LOG.exception("InvalidContentType: %s", msg)
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))
        except exception.MalformedRequestBody:
            msg = _("Malformed request body")
            LOG.exception("MalformedRequestBody: %s", msg)
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))

        try:
            action_result = self.dispatch(request, action, args)
        except webob.exc.HTTPException as ex:
            LOG.info("HTTP exception thrown: %s", ex)
            action_result = Fault(ex, self._fault_body_function)
        except Exception:
            LOG.exception("Internal error")
            # Do not include the traceback to avoid returning it to clients.
            action_result = Fault(webob.exc.HTTPServerError(),
                                  self._fault_body_function)

        if isinstance(action_result, dict) or action_result is None:
            response = self.serializer.serialize(action_result,
                                                 accept,
                                                 action=action)
        else:
            response = action_result

        try:
            LOG.info("%(url)s returned with HTTP %(status)d",
                     dict(url=request.url, status=response.status_int))
        except AttributeError as e:
            LOG.info("%(url)s returned a fault: %(exception)s",
                     dict(url=request.url, exception=e))

        return response

    def dispatch(self, request, action, action_args):
        """Find action-specific method on controller and call it."""

        controller_method = getattr(self.controller, action)
        try:
            # NOTE(salvatore-orlando): the controller method must have
            # an argument whose name is 'request'
            return controller_method(request=request, **action_args)
        except TypeError:
            LOG.exception('Invalid request')
            return Fault(webob.exc.HTTPBadRequest())


def _default_body_function(wrapped_exc):
    code = wrapped_exc.status_int
    fault_data = {
        'Error': {
            'code': code,
            'message': wrapped_exc.explanation}}
    # 'code' is an attribute on the fault tag itself
    metadata = {'attributes': {'Error': 'code'}}
    return fault_data, metadata


class Fault(webob.exc.HTTPException):
    """Generates an HTTP response from a webob HTTP exception."""

    def __init__(self, exception, body_function=None):
        """Creates a Fault for the given webob.exc.exception."""
        self.wrapped_exc = exception
        self.status_int = self.wrapped_exc.status_int
        self._body_function = body_function or _default_body_function

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        """Generate a WSGI response based on the exception passed to ctor."""
        # Replace the body with fault details.
        fault_data, metadata = self._body_function(self.wrapped_exc)
        content_type = req.best_match_content_type()
        serializer = {
            'application/json': JSONDictSerializer(),
        }[content_type]

        self.wrapped_exc.body = serializer.serialize(fault_data)
        self.wrapped_exc.content_type = content_type
        return self.wrapped_exc


# NOTE(salvatore-orlando): this class will go once the
# extension API framework is updated
class Controller(object):
    """WSGI app that dispatched to methods.

    WSGI app that reads routing information supplied by RoutesMiddleware
    and calls the requested action method upon itself.  All action methods
    must, in addition to their normal parameters, accept a 'req' argument
    which is the incoming wsgi.Request.  They raise a webob.exc exception,
    or return a dict which will be serialized by requested content type.

    """

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        """Call the method specified in req.environ by RoutesMiddleware."""
        arg_dict = req.environ['wsgiorg.routing_args'][1]
        action = arg_dict['action']
        method = getattr(self, action)
        del arg_dict['controller']
        del arg_dict['action']
        if 'format' in arg_dict:
            del arg_dict['format']
        arg_dict['request'] = req
        result = method(**arg_dict)

        if isinstance(result, dict) or result is None:
            if result is None:
                status = 204
                content_type = ''
                body = None
            else:
                status = 200
                content_type = req.best_match_content_type()
                body = self._serialize(result, content_type)

            response = webob.Response(status=status,
                                      content_type=content_type,
                                      body=body)
            LOG.debug("%(url)s returned with HTTP %(status)d",
                      dict(url=req.url, status=response.status_int))
            return response
        else:
            return result

    def _serialize(self, data, content_type):
        """Serialize the given dict to the provided content_type.

        Uses self._serialization_metadata if it exists, which is a dict mapping
        MIME types to information needed to serialize to that type.

        """
        _metadata = getattr(type(self), '_serialization_metadata', {})

        serializer = Serializer(_metadata)
        try:
            return serializer.serialize(data, content_type)
        except exception.InvalidContentType:
            msg = _('The requested content type %s is invalid.') % content_type
            raise webob.exc.HTTPNotAcceptable(msg)

    def _deserialize(self, data, content_type):
        """Deserialize the request body to the specified content type.

        Uses self._serialization_metadata if it exists, which is a dict mapping
        MIME types to information needed to serialize to that type.

        """
        _metadata = getattr(type(self), '_serialization_metadata', {})
        serializer = Serializer(_metadata)
        return serializer.deserialize(data, content_type)['body']


# NOTE(salvatore-orlando): this class will go once the
# extension API framework is updated
class Serializer(object):
    """Serializes and deserializes dictionaries to certain MIME types."""

    def __init__(self, metadata=None):
        """Create a serializer based on the given WSGI environment.

        'metadata' is an optional dict mapping MIME types to information
        needed to serialize a dictionary to that type.

        """
        self.metadata = metadata or {}

    def _get_serialize_handler(self, content_type):
        handlers = {
            'application/json': JSONDictSerializer(),
        }

        try:
            return handlers[content_type]
        except Exception:
            raise exception.InvalidContentType(content_type=content_type)

    def serialize(self, data, content_type):
        """Serialize a dictionary into the specified content type."""
        return self._get_serialize_handler(content_type).serialize(data)

    def deserialize(self, datastring, content_type):
        """Deserialize a string to a dictionary.

        The string must be in the format of a supported MIME type.

        """
        try:
            return self.get_deserialize_handler(content_type).deserialize(
                datastring)
        except Exception:
            raise webob.exc.HTTPBadRequest(_("Could not deserialize data"))

    def get_deserialize_handler(self, content_type):
        handlers = {
            'application/json': JSONDeserializer(),
        }

        try:
            return handlers[content_type]
        except Exception:
            raise exception.InvalidContentType(content_type=content_type)
