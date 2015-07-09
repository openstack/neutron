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

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_messaging import serializer as om_serializer
from oslo_service import service

from neutron.common import exceptions
from neutron import context


LOG = logging.getLogger(__name__)


TRANSPORT = None
NOTIFIER = None

ALLOWED_EXMODS = [
    exceptions.__name__,
]
EXTRA_EXMODS = []


TRANSPORT_ALIASES = {
    'neutron.openstack.common.rpc.impl_fake': 'fake',
    'neutron.openstack.common.rpc.impl_qpid': 'qpid',
    'neutron.openstack.common.rpc.impl_kombu': 'rabbit',
    'neutron.openstack.common.rpc.impl_zmq': 'zmq',
    'neutron.rpc.impl_fake': 'fake',
    'neutron.rpc.impl_qpid': 'qpid',
    'neutron.rpc.impl_kombu': 'rabbit',
    'neutron.rpc.impl_zmq': 'zmq',
}


def init(conf):
    global TRANSPORT, NOTIFIER
    exmods = get_allowed_exmods()
    TRANSPORT = oslo_messaging.get_transport(conf,
                                             allowed_remote_exmods=exmods,
                                             aliases=TRANSPORT_ALIASES)
    serializer = RequestContextSerializer()
    NOTIFIER = oslo_messaging.Notifier(TRANSPORT, serializer=serializer)


def cleanup():
    global TRANSPORT, NOTIFIER
    assert TRANSPORT is not None
    assert NOTIFIER is not None
    TRANSPORT.cleanup()
    TRANSPORT = NOTIFIER = None


def add_extra_exmods(*args):
    EXTRA_EXMODS.extend(args)


def clear_extra_exmods():
    del EXTRA_EXMODS[:]


def get_allowed_exmods():
    return ALLOWED_EXMODS + EXTRA_EXMODS


def get_client(target, version_cap=None, serializer=None):
    assert TRANSPORT is not None
    serializer = RequestContextSerializer(serializer)
    return oslo_messaging.RPCClient(TRANSPORT,
                                    target,
                                    version_cap=version_cap,
                                    serializer=serializer)


def get_server(target, endpoints, serializer=None):
    assert TRANSPORT is not None
    serializer = RequestContextSerializer(serializer)
    return oslo_messaging.get_rpc_server(TRANSPORT, target, endpoints,
                                         'eventlet', serializer)


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
        return ctxt.to_dict()

    def deserialize_context(self, ctxt):
        rpc_ctxt_dict = ctxt.copy()
        user_id = rpc_ctxt_dict.pop('user_id', None)
        if not user_id:
            user_id = rpc_ctxt_dict.pop('user', None)
        tenant_id = rpc_ctxt_dict.pop('tenant_id', None)
        if not tenant_id:
            tenant_id = rpc_ctxt_dict.pop('project_id', None)
        return context.Context(user_id, tenant_id, **rpc_ctxt_dict)


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

        self.conn = create_connection(new=True)
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
        except Exception:
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


# functions
def create_connection(new=True):
    return Connection()
