# Copyright (c) 2012 OpenStack Foundation.
# Copyright (c) 2014 Red Hat, Inc.
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

import collections
import random
import time

from neutron_lib import context
from neutron_lib import exceptions as lib_exceptions
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_messaging.rpc import dispatcher
from oslo_messaging import serializer as om_serializer
from oslo_service import service
from oslo_utils import excutils
from osprofiler import profiler

from neutron.common import exceptions


LOG = logging.getLogger(__name__)


TRANSPORT = None
NOTIFICATION_TRANSPORT = None
NOTIFIER = None

ALLOWED_EXMODS = [
    exceptions.__name__,
    lib_exceptions.__name__,
]
EXTRA_EXMODS = []


# NOTE(salv-orlando): I am afraid this is a global variable. While not ideal,
# they're however widely used throughout the code base. It should be set to
# true if the RPC server is not running in the current process space. This
# will prevent get_connection from creating connections to the AMQP server
RPC_DISABLED = False


def init(conf):
    global TRANSPORT, NOTIFICATION_TRANSPORT, NOTIFIER
    exmods = get_allowed_exmods()
    TRANSPORT = oslo_messaging.get_rpc_transport(conf,
                                                 allowed_remote_exmods=exmods)
    NOTIFICATION_TRANSPORT = oslo_messaging.get_notification_transport(
        conf, allowed_remote_exmods=exmods)
    serializer = RequestContextSerializer()
    NOTIFIER = oslo_messaging.Notifier(NOTIFICATION_TRANSPORT,
                                       serializer=serializer)


def cleanup():
    global TRANSPORT, NOTIFICATION_TRANSPORT, NOTIFIER
    assert TRANSPORT is not None
    assert NOTIFICATION_TRANSPORT is not None
    assert NOTIFIER is not None
    TRANSPORT.cleanup()
    NOTIFICATION_TRANSPORT.cleanup()
    _BackingOffContextWrapper.reset_timeouts()
    TRANSPORT = NOTIFICATION_TRANSPORT = NOTIFIER = None


def add_extra_exmods(*args):
    EXTRA_EXMODS.extend(args)


def clear_extra_exmods():
    del EXTRA_EXMODS[:]


def get_allowed_exmods():
    return ALLOWED_EXMODS + EXTRA_EXMODS


def _get_default_method_timeout():
    return TRANSPORT.conf.rpc_response_timeout


def _get_default_method_timeouts():
    return collections.defaultdict(_get_default_method_timeout)


class _ContextWrapper(object):
    def __init__(self, original_context):
        self._original_context = original_context

    def __getattr__(self, name):
        return getattr(self._original_context, name)

    def cast(self, ctxt, method, **kwargs):
        try:
            self._original_context.cast(ctxt, method, **kwargs)
        except Exception as e:
            # TODO(kevinbenton): make catch specific to missing exchange once
            # bug/1705351 is resolved on the oslo.messaging side; if
            # oslo.messaging auto-creates the exchange, then just remove the
            # code completely
            LOG.debug("Ignored exception during cast: %e", e)


class _BackingOffContextWrapper(_ContextWrapper):
    """Wraps oslo messaging contexts to set the timeout for calls.

    This intercepts RPC calls and sets the timeout value to the globally
    adapting value for each method. An oslo messaging timeout results in
    a doubling of the timeout value for the method on which it timed out.
    There currently is no logic to reduce the timeout since busy Neutron
    servers are more frequently the cause of timeouts rather than lost
    messages.
    """
    _METHOD_TIMEOUTS = _get_default_method_timeouts()
    _max_timeout = None

    @classmethod
    def reset_timeouts(cls):
        # restore the original default timeout factory
        cls._METHOD_TIMEOUTS = _get_default_method_timeouts()
        cls._max_timeout = None

    @classmethod
    def get_max_timeout(cls):
        return cls._max_timeout or _get_default_method_timeout() * 10

    @classmethod
    def set_max_timeout(cls, max_timeout):
        if max_timeout < cls.get_max_timeout():
            cls._METHOD_TIMEOUTS = collections.defaultdict(
                lambda: max_timeout, **{
                    k: min(v, max_timeout)
                    for k, v in cls._METHOD_TIMEOUTS.items()
                })
            cls._max_timeout = max_timeout

    def call(self, ctxt, method, **kwargs):
        # two methods with the same name in different namespaces should
        # be tracked independently
        if self._original_context.target.namespace:
            scoped_method = '%s.%s' % (self._original_context.target.namespace,
                                       method)
        else:
            scoped_method = method
        # set the timeout from the global method timeout tracker for this
        # method
        self._original_context.timeout = self._METHOD_TIMEOUTS[scoped_method]
        try:
            return self._original_context.call(ctxt, method, **kwargs)
        except oslo_messaging.MessagingTimeout:
            with excutils.save_and_reraise_exception():
                wait = random.uniform(
                    0,
                    min(self._METHOD_TIMEOUTS[scoped_method],
                        TRANSPORT.conf.rpc_response_timeout)
                )
                LOG.error("Timeout in RPC method %(method)s. Waiting for "
                          "%(wait)s seconds before next attempt. If the "
                          "server is not down, consider increasing the "
                          "rpc_response_timeout option as Neutron "
                          "server(s) may be overloaded and unable to "
                          "respond quickly enough.",
                          {'wait': int(round(wait)), 'method': scoped_method})
                new_timeout = min(
                    self._original_context.timeout * 2, self.get_max_timeout())
                if new_timeout > self._METHOD_TIMEOUTS[scoped_method]:
                    LOG.warning("Increasing timeout for %(method)s calls "
                                "to %(new)s seconds. Restart the agent to "
                                "restore it to the default value.",
                                {'method': scoped_method, 'new': new_timeout})
                    self._METHOD_TIMEOUTS[scoped_method] = new_timeout
                time.sleep(wait)


class BackingOffClient(oslo_messaging.RPCClient):
    """An oslo messaging RPC Client that implements a timeout backoff.

    This has all of the same interfaces as oslo_messaging.RPCClient but
    if the timeout parameter is not specified, the _BackingOffContextWrapper
    returned will track when call timeout exceptions occur and exponentially
    increase the timeout for the given call method.
    """
    def prepare(self, *args, **kwargs):
        ctx = super(BackingOffClient, self).prepare(*args, **kwargs)
        # don't back off contexts that explicitly set a timeout
        if 'timeout' in kwargs:
            return _ContextWrapper(ctx)
        return _BackingOffContextWrapper(ctx)

    @staticmethod
    def set_max_timeout(max_timeout):
        '''Set RPC timeout ceiling for all backing-off RPC clients.'''
        _BackingOffContextWrapper.set_max_timeout(max_timeout)


def get_client(target, version_cap=None, serializer=None):
    assert TRANSPORT is not None
    serializer = RequestContextSerializer(serializer)
    return BackingOffClient(TRANSPORT,
                            target,
                            version_cap=version_cap,
                            serializer=serializer)


def get_server(target, endpoints, serializer=None):
    assert TRANSPORT is not None
    serializer = RequestContextSerializer(serializer)
    access_policy = dispatcher.DefaultRPCAccessPolicy
    return oslo_messaging.get_rpc_server(TRANSPORT, target, endpoints,
                                         'eventlet', serializer,
                                         access_policy=access_policy)


def get_notifier(service=None, host=None, publisher_id=None):
    assert NOTIFIER is not None
    if not publisher_id:
        publisher_id = "%s.%s" % (service, host or cfg.CONF.host)
    return NOTIFIER.prepare(publisher_id=publisher_id)


class RequestContextSerializer(om_serializer.Serializer):
    """This serializer is used to convert RPC common context into
    Neutron Context.
    """
    def __init__(self, base=None):
        super(RequestContextSerializer, self).__init__()
        self._base = base

    def serialize_entity(self, ctxt, entity):
        if not self._base:
            return entity
        return self._base.serialize_entity(ctxt, entity)

    def deserialize_entity(self, ctxt, entity):
        if not self._base:
            return entity
        return self._base.deserialize_entity(ctxt, entity)

    def serialize_context(self, ctxt):
        _context = ctxt.to_dict()
        prof = profiler.get()
        if prof:
            trace_info = {
                "hmac_key": prof.hmac_key,
                "base_id": prof.get_base_id(),
                "parent_id": prof.get_id()
            }
            _context['trace_info'] = trace_info
        return _context

    def deserialize_context(self, ctxt):
        rpc_ctxt_dict = ctxt.copy()
        trace_info = rpc_ctxt_dict.pop("trace_info", None)
        if trace_info:
            profiler.init(**trace_info)
        return context.Context.from_dict(rpc_ctxt_dict)


@profiler.trace_cls("rpc")
class Service(service.Service):
    """Service object for binaries running on hosts.

    A service enables rpc by listening to queues based on topic and host.
    """
    def __init__(self, host, topic, manager=None, serializer=None):
        super(Service, self).__init__()
        self.host = host
        self.topic = topic
        self.serializer = serializer
        if manager is None:
            self.manager = self
        else:
            self.manager = manager

    def start(self):
        super(Service, self).start()

        self.conn = create_connection()
        LOG.debug("Creating Consumer connection for Service %s",
                  self.topic)

        endpoints = [self.manager]

        self.conn.create_consumer(self.topic, endpoints)

        # Hook to allow the manager to do other initializations after
        # the rpc connection is created.
        if callable(getattr(self.manager, 'initialize_service_hook', None)):
            self.manager.initialize_service_hook(self)

        # Consume from all consumers in threads
        self.conn.consume_in_threads()

    def stop(self):
        # Try to shut the connection down, but if we get any sort of
        # errors, go ahead and ignore them.. as we're shutting down anyway
        try:
            self.conn.close()
        except Exception:  # nosec
            pass
        super(Service, self).stop()


class Connection(object):

    def __init__(self):
        super(Connection, self).__init__()
        self.servers = []

    def create_consumer(self, topic, endpoints, fanout=False):
        target = oslo_messaging.Target(
            topic=topic, server=cfg.CONF.host, fanout=fanout)
        server = get_server(target, endpoints)
        self.servers.append(server)

    def consume_in_threads(self):
        for server in self.servers:
            server.start()
        return self.servers

    def close(self):
        for server in self.servers:
            server.stop()
        for server in self.servers:
            server.wait()


class VoidConnection(object):

    def create_consumer(self, topic, endpoints, fanout=False):
        pass

    def consume_in_threads(self):
        pass

    def close(self):
        pass


# functions
def create_connection():
    # NOTE(salv-orlando): This is a clever interpretation of the factory design
    # patter aimed at preventing plugins from initializing RPC servers upon
    # initialization when they are running in the REST over HTTP API server.
    # The educated reader will perfectly be able that this a fairly dirty hack
    # to avoid having to change the initialization process of every plugin.
    if RPC_DISABLED:
        return VoidConnection()
    return Connection()
