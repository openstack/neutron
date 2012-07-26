# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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
import logging
import socket
import sys
import time
import uuid

from sqlalchemy.ext import sqlsoup

from quantum.agent.common import config
from quantum.agent.linux import dhcp
from quantum.agent.linux import interface
from quantum.agent.linux import ip_lib
from quantum.common import exceptions
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils
from quantum.version import version_string
from quantumclient.v2_0 import client

LOG = logging.getLogger(__name__)

State = collections.namedtuple('State',
                               ['networks', 'subnet_hashes', 'ipalloc_hashes'])


class DhcpAgent(object):
    OPTS = [
        cfg.StrOpt('db_connection', default=''),
        cfg.StrOpt('root_helper', default='sudo'),
        cfg.StrOpt('dhcp_driver',
                   default='quantum.agent.linux.dhcp.Dnsmasq',
                   help="The driver used to manage the DHCP server."),
        cfg.IntOpt('polling_interval',
                   default=3,
                   help="The time in seconds between state poll requests."),
        cfg.IntOpt('reconnect_interval',
                   default=5,
                   help="The time in seconds between db reconnect attempts.")
    ]

    def __init__(self, conf):
        self.conf = conf
        self.dhcp_driver_cls = importutils.import_class(conf.dhcp_driver)
        self.db = None
        self.polling_interval = conf.polling_interval
        self.reconnect_interval = conf.reconnect_interval
        self._run = True
        self.prev_state = State(set(), set(), set())

    def daemon_loop(self):
        while self._run:
            delta = self.get_network_state_delta()
            if delta is None:
                continue

            for network in delta.get('new', []):
                self.call_driver('enable', network)
            for network in delta.get('updated', []):
                self.call_driver('reload_allocations', network)
            for network in delta.get('deleted', []):
                self.call_driver('disable', network)

            time.sleep(self.polling_interval)

    def _state_builder(self):
        """Polls the Quantum database and returns a represenation
        of the network state.

        The value returned is a State tuple that contains three sets:
        networks, subnet_hashes, and ipalloc_hashes.

        The hash sets are a tuple that contains the computed signature of the
        obejct's metadata and the network that owns it.  Signatures are used
        because the objects metadata can change.  Python's built-in hash
        function is used on the string repr to compute the metadata signature.
        """
        try:
            if self.db is None:
                time.sleep(self.reconnect_interval)
                self.db = sqlsoup.SqlSoup(self.conf.db_connection)
                LOG.info("Connecting to database \"%s\" on %s" %
                         (self.db.engine.url.database,
                          self.db.engine.url.host))
            else:
                # we have to commit to get the latest view
                self.db.commit()

            subnets = {}
            subnet_hashes = set()

            network_admin_up = {}
            for network in self.db.networks.all():
                network_admin_up[network.id] = network.admin_state_up

            for subnet in self.db.subnets.all():
                if (not subnet.enable_dhcp or
                        not network_admin_up[subnet.network_id]):
                    continue
                subnet_hashes.add((hash(str(subnet)), subnet.network_id))
                subnets[subnet.id] = subnet.network_id

            ipalloc_hashes = set([(hash(str(a)), subnets[a.subnet_id])
                                 for a in self.db.ipallocations.all()
                                 if a.subnet_id in subnets])

            networks = set(subnets.itervalues())

            return State(networks, subnet_hashes, ipalloc_hashes)

        except Exception, e:
            LOG.warn('Unable to get network state delta. Exception: %s' % e)
            self.db = None
            return None

    def get_network_state_delta(self):
        """Return a dict containing the sets of networks that are new,
        updated, and deleted."""
        delta = {}
        state = self._state_builder()

        if state is None:
            return None

        # determine the new/deleted networks
        delta['deleted'] = self.prev_state.networks - state.networks
        delta['new'] = state.networks - self.prev_state.networks

        # Get the networks that have subnets added or deleted.
        # The change candidates are the net_id portion of the symmetric diff
        # between the sets of (subnet_hash,net_id)
        candidates = set(
            [h[1] for h in
                (state.subnet_hashes ^ self.prev_state.subnet_hashes)]
        )

        # Update with the networks that have had allocations added/deleted.
        # change candidates are the net_id portion of the symmetric diff
        # between the sets of (alloc_hash,net_id)
        candidates.update(
            [h[1] for h in
                (state.ipalloc_hashes ^ self.prev_state.ipalloc_hashes)]
        )

        # the updated set will contain new and deleted networks, so remove them
        delta['updated'] = candidates - delta['new'] - delta['deleted']

        self.prev_state = state

        return delta

    def call_driver(self, action, network_id):
        """Invoke an action on a DHCP driver instance."""
        try:
            # the Driver expects something that is duck typed similar to
            # the base models.  Augmenting will add support to the SqlSoup
            # result, so that the Driver does have to concern itself with our
            # db schema.
            network = AugmentingWrapper(
                self.db.networks.filter_by(id=network_id).one(),
                self.db
            )
            driver = self.dhcp_driver_cls(self.conf,
                                          network,
                                          self.conf.root_helper,
                                          DeviceManager(self.conf, self.db))
            getattr(driver, action)()

        except Exception, e:
            LOG.warn('Unable to %s dhcp. Exception: %s' % (action, e))

            # Manipulate the state so the action will be attempted on next
            # loop iteration.
            if action == 'disable':
                # adding to prev state means we'll try to delete it next time
                self.prev_state.networks.add(network_id)
            else:
                # removing means it will look like new next time
                self.prev_state.networks.remove(network_id)


class DeviceManager(object):
    OPTS = [
        cfg.StrOpt('admin_user'),
        cfg.StrOpt('admin_password'),
        cfg.StrOpt('admin_tenant_name'),
        cfg.StrOpt('auth_url'),
        cfg.StrOpt('auth_strategy', default='keystone'),
        cfg.StrOpt('auth_region'),
        cfg.StrOpt('interface_driver',
                   help="The driver used to manage the virtual interface.")
    ]

    def __init__(self, conf, db):
        self.conf = conf
        self.db = db

        if not conf.interface_driver:
            LOG.error(_('You must specify an interface driver'))
        self.driver = importutils.import_object(conf.interface_driver, conf)

    def get_interface_name(self, network, port=None):
        if not port:
            port = self._get_or_create_port(network)
        return self.driver.get_device_name(port)

    def get_device_id(self, network):
        # There could be more than one dhcp server per network, so create
        # a device id that combines host and network ids

        host_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname())
        return 'dhcp%s-%s' % (host_uuid, network.id)

    def setup(self, network, reuse_existing=False):
        port = self._get_or_create_port(network)
        interface_name = self.get_interface_name(network, port)

        if ip_lib.device_exists(interface_name):
            if not reuse_existing:
                raise exceptions.PreexistingDeviceFailure(
                    dev_name=interface_name)

            LOG.debug(_('Reusing existing device: %s.') % interface_name)
        else:
            self.driver.plug(network.id,
                             port.id,
                             interface_name,
                             port.mac_address)
        self.driver.init_l3(port, interface_name)

    def destroy(self, network):
        self.driver.unplug(self.get_interface_name(network))

    def _get_or_create_port(self, network):
        # todo (mark): reimplement using RPC
        # Usage of client lib is a temporary measure.

        try:
            device_id = self.get_device_id(network)
            port_obj = self.db.ports.filter_by(device_id=device_id).one()
            port = AugmentingWrapper(port_obj, self.db)
        except sqlsoup.SQLAlchemyError, e:
            port = self._create_port(network)

        return port

    def _create_port(self, network):
        # todo (mark): reimplement using RPC
        # Usage of client lib is a temporary measure.

        quantum = client.Client(
            username=self.conf.admin_user,
            password=self.conf.admin_password,
            tenant_name=self.conf.admin_tenant_name,
            auth_url=self.conf.auth_url,
            auth_strategy=self.conf.auth_strategy,
            auth_region=self.conf.auth_region
        )

        body = dict(port=dict(
            admin_state_up=True,
            device_id=self.get_device_id(network),
            network_id=network.id,
            tenant_id=network.tenant_id,
            fixed_ips=[dict(subnet_id=s.id) for s in network.subnets]))
        port_dict = quantum.create_port(body)['port']

        # we have to call commit since the port was created in outside of
        # our current transaction
        self.db.commit()

        port = AugmentingWrapper(
            self.db.ports.filter_by(id=port_dict['id']).one(),
            self.db)
        return port


class PortModel(object):
    def __init__(self, port_dict):
        self.__dict__.update(port_dict)


class AugmentingWrapper(object):
    """A wrapper that augments Sqlsoup results so that they look like the
    base v2 db model.
    """

    MAPPING = {
        'networks': {'subnets': 'subnets', 'ports': 'ports'},
        'subnets': {'allocations': 'ipallocations'},
        'ports': {'fixed_ips': 'ipallocations'},

    }

    def __init__(self, obj, db):
        self.obj = obj
        self.db = db

    def __repr__(self):
        return repr(self.obj)

    def __getattr__(self, name):
        """Executes a dynamic lookup of attributes to make SqlSoup results
        mimic the same structure as the v2 db models.

        The actual models could not be used because they're dependent on the
        plugin and the agent is not tied to any plugin structure.

        If .subnet, is accessed, the wrapper will return a subnet
        object if this instance has a subnet_id attribute.

        If the _id attribute does not exists then wrapper will check MAPPING
        to see if a reverse relationship exists.  If so, a wrapped result set
        will be returned.
        """

        try:
            return getattr(self.obj, name)
        except:
            pass

        id_attr = '%s_id' % name
        if hasattr(self.obj, id_attr):
            args = {'id': getattr(self.obj, id_attr)}
            return AugmentingWrapper(
                getattr(self.db, '%ss' % name).filter_by(**args).one(),
                self.db
            )
        try:
            attr_name = self.MAPPING[self.obj._table.name][name]
            arg_name = '%s_id' % self.obj._table.name[:-1]
            args = {arg_name: self.obj.id}

            return [AugmentingWrapper(o, self.db) for o in
                    getattr(self.db, attr_name).filter_by(**args).all()]
        except KeyError:
            pass

        raise AttributeError


def main():
    conf = config.setup_conf()
    conf.register_opts(DhcpAgent.OPTS)
    conf.register_opts(DeviceManager.OPTS)
    conf.register_opts(dhcp.OPTS)
    conf.register_opts(interface.OPTS)
    conf(sys.argv)
    config.setup_logging(conf)

    mgr = DhcpAgent(conf)
    mgr.daemon_loop()


if __name__ == '__main__':
    main()
