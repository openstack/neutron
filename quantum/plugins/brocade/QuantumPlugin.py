# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Brocade Communications System, Inc.
# All rights reserved.
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
#
# Authors:
# Shiv Haris (sharis@brocade.com)
# Varma Bhupatiraju (vbhupati@#brocade.com)
#
# (Some parts adapted from LinuxBridge Plugin)
# TODO (shiv) need support for security groups


"""
Implentation of Brocade Quantum Plugin.
"""

from oslo.config import cfg

from quantum.agent import securitygroups_rpc as sg_rpc
from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from quantum.api.rpc.agentnotifiers import l3_rpc_agent_api
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.common import utils
from quantum.db import agents_db
from quantum.db import agentschedulers_db
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import l3_rpc_base
from quantum.db import securitygroups_rpc_base as sg_db_rpc
from quantum.extensions import portbindings
from quantum.extensions import securitygroup as ext_sg
from quantum.openstack.common import context
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import proxy
from quantum.plugins.brocade.db import models as brocade_db
from quantum.plugins.brocade import vlanbm as vbm
from quantum import policy
from quantum import scheduler


LOG = logging.getLogger(__name__)
PLUGIN_VERSION = 0.88
AGENT_OWNER_PREFIX = "network:"
NOS_DRIVER = 'quantum.plugins.brocade.nos.nosdriver.NOSdriver'

SWITCH_OPTS = [cfg.StrOpt('address', default=''),
               cfg.StrOpt('username', default=''),
               cfg.StrOpt('password', default='', secret=True),
               cfg.StrOpt('ostype', default='NOS')
               ]

PHYSICAL_INTERFACE_OPTS = [cfg.StrOpt('physical_interface', default='eth0')
                           ]

cfg.CONF.register_opts(SWITCH_OPTS, "SWITCH")
cfg.CONF.register_opts(PHYSICAL_INTERFACE_OPTS, "PHYSICAL_INTERFACE")
cfg.CONF.register_opts(scheduler.AGENTS_SCHEDULER_OPTS)


class BridgeRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                         l3_rpc_base.L3RpcCallbackMixin,
                         sg_db_rpc.SecurityGroupServerRpcCallbackMixin):
    """Agent callback."""

    RPC_API_VERSION = '1.1'
    # Device names start with "tap"
    # history
    #   1.1 Support Security Group RPC
    TAP_PREFIX_LEN = 3

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])

    @classmethod
    def get_port_from_device(cls, device):
        """Get port from the brocade specific db."""

        # TODO(shh) context is not being passed as
        # an argument to this function;
        #
        # need to be fixed in:
        # file: quantum/db/securtygroups_rpc_base.py
        # function: securitygroup_rules_for_devices()
        # which needs to pass context to us

        # Doing what other plugins are doing
        session = db.get_session()
        port = brocade_db.get_port_from_device(
            session, device[cls.TAP_PREFIX_LEN:])

        # TODO(shiv): need to extend the db model to include device owners
        # make it appears that the device owner is of type network
        if port:
            port['device'] = device
            port['device_owner'] = AGENT_OWNER_PREFIX
            port['binding:vif_type'] = 'bridge'
        return port

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details."""

        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s details requested from %(agent_id)s"),
                  locals())
        port = brocade_db.get_port(rpc_context, device[self.TAP_PREFIX_LEN:])
        if port:
            entry = {'device': device,
                     'vlan_id': port.vlan_id,
                     'network_id': port.network_id,
                     'port_id': port.port_id,
                     'physical_network': port.physical_interface,
                     'admin_state_up': port.admin_state_up
                     }

        else:
            entry = {'device': device}
            LOG.debug(_("%s can not be found in database"), device)
        return entry

    def update_device_down(self, rpc_context, **kwargs):
        """Device no longer exists on agent."""

        device = kwargs.get('device')
        port = self.get_port_from_device(device)
        if port:
            entry = {'device': device,
                     'exists': True}
            # Set port status to DOWN
            port_id = port['port_id']
            brocade_db.update_port_state(rpc_context, port_id, False)
        else:
            entry = {'device': device,
                     'exists': False}
            LOG.debug(_("%s can not be found in database"), device)
        return entry


class AgentNotifierApi(proxy.RpcProxy,
                       sg_rpc.SecurityGroupAgentRpcApiMixin):
    '''Agent side of the linux bridge rpc API.

    API version history:
        1.0 - Initial version.

    '''

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic = topic
        self.topic_network_delete = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.DELETE)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)

    def network_delete(self, context, network_id):
        self.fanout_cast(context,
                         self.make_msg('network_delete',
                                       network_id=network_id),
                         topic=self.topic_network_delete)

    def port_update(self, context, port, physical_network, vlan_id):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port,
                                       physical_network=physical_network,
                                       vlan_id=vlan_id),
                         topic=self.topic_port_update)


class BrocadePluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                      sg_db_rpc.SecurityGroupServerRpcMixin,
                      agentschedulers_db.AgentSchedulerDbMixin):
    """BrocadePluginV2 is a Quantum plugin.

    Provides L2 Virtual Network functionality using VDX. Upper
    layer driver class that interfaces to NETCONF layer below.

    """

    def __init__(self):
        """Initialize Brocade Plugin, specify switch address
        and db configuration.
        """

        self.supported_extension_aliases = ["binding", "security-group",
                                            "agent", "agent_scheduler"]
        self.binding_view = "extension:port_binding:view"
        self.binding_set = "extension:port_binding:set"

        self.physical_interface = (cfg.CONF.PHYSICAL_INTERFACE.
                                   physical_interface)
        db.configure_db()
        self.ctxt = context.get_admin_context()
        self.ctxt.session = db.get_session()
        self._vlan_bitmap = vbm.VlanBitmap(self.ctxt)
        self._setup_rpc()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver)
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)
        self.brocade_init()

    def brocade_init(self):
        """Brocade specific initialization."""

        self._switch = {'address': cfg.CONF.SWITCH.address,
                        'username': cfg.CONF.SWITCH.username,
                        'password': cfg.CONF.SWITCH.password
                        }
        self._driver = importutils.import_object(NOS_DRIVER)

    def _setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.rpc_context = context.RequestContext('quantum', 'quantum',
                                                  is_admin=False)
        self.conn = rpc.create_connection(new=True)
        self.callbacks = BridgeRpcCallbacks()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.l3_agent_notifier = l3_rpc_agent_api.L3AgentNotify

    def create_network(self, context, network):
        """This call to create network translates to creation of
        port-profile on the physical switch.
        """

        with context.session.begin(subtransactions=True):
            net = super(BrocadePluginV2, self).create_network(context, network)
            net_uuid = net['id']
            vlan_id = self._vlan_bitmap.get_next_vlan(None)
            switch = self._switch
            try:
                self._driver.create_network(switch['address'],
                                            switch['username'],
                                            switch['password'],
                                            vlan_id)
            except Exception as e:
                # Proper formatting
                LOG.warning(_("Brocade NOS driver:"))
                LOG.warning(_("%s"), e)
                LOG.debug(_("Returning the allocated vlan (%d) to the pool"),
                          vlan_id)
                self._vlan_bitmap.release_vlan(int(vlan_id))
                raise Exception("Brocade plugin raised exception, check logs")

            brocade_db.create_network(context, net_uuid, vlan_id)

        LOG.info(_("Allocated vlan (%d) from the pool"), vlan_id)
        return net

    def delete_network(self, context, net_id):
        """This call to delete the network translates to removing
        the port-profile on the physical switch.
        """

        with context.session.begin(subtransactions=True):
            result = super(BrocadePluginV2, self).delete_network(context,
                                                                 net_id)
            # we must delete all ports in db first (foreign key constraint)
            # there is no need to delete port in the driver (its a no-op)
            # (actually: note there is no such call to the driver)
            bports = brocade_db.get_ports(context, net_id)
            for bport in bports:
                brocade_db.delete_port(context, bport['port_id'])

            # find the vlan for this network
            net = brocade_db.get_network(context, net_id)
            vlan_id = net['vlan']

            # Tell hw to do remove PP
            switch = self._switch
            try:
                self._driver.delete_network(switch['address'],
                                            switch['username'],
                                            switch['password'],
                                            net_id)
            except Exception as e:
                # Proper formatting
                LOG.warning(_("Brocade NOS driver:"))
                LOG.warning(_("%s"), e)
                raise Exception("Brocade plugin raised exception, check logs")

            # now ok to delete the network
            brocade_db.delete_network(context, net_id)

        # relinquish vlan in bitmap
        self._vlan_bitmap.release_vlan(int(vlan_id))
        return result

    def create_port(self, context, port):
        """Create logical port on the switch."""

        tenant_id = port['port']['tenant_id']
        network_id = port['port']['network_id']
        admin_state_up = port['port']['admin_state_up']

        physical_interface = self.physical_interface

        with context.session.begin(subtransactions=True):
            bnet = brocade_db.get_network(context, network_id)
            vlan_id = bnet['vlan']

            quantum_port = super(BrocadePluginV2, self).create_port(context,
                                                                    port)
            interface_mac = quantum_port['mac_address']
            port_id = quantum_port['id']

            switch = self._switch

            # convert mac format: xx:xx:xx:xx:xx:xx -> xxxx.xxxx.xxxx
            mac = self.mac_reformat_62to34(interface_mac)
            try:
                self._driver.associate_mac_to_network(switch['address'],
                                                      switch['username'],
                                                      switch['password'],
                                                      vlan_id,
                                                      mac)
            except Exception as e:
                # Proper formatting
                LOG.warning(_("Brocade NOS driver:"))
                LOG.warning(_("%s"), e)
                raise Exception("Brocade plugin raised exception, check logs")

            # save to brocade persistent db
            brocade_db.create_port(context, port_id, network_id,
                                   physical_interface,
                                   vlan_id, tenant_id, admin_state_up)

        # apply any extensions
        return self._extend_port_dict_binding(context, quantum_port)

    def delete_port(self, context, port_id):
        with context.session.begin(subtransactions=True):
            super(BrocadePluginV2, self).delete_port(context, port_id)
            brocade_db.delete_port(context, port_id)

    def update_port(self, context, port_id, port):
        original_port = self.get_port(context, port_id)
        session = context.session
        port_updated = False
        with session.begin(subtransactions=True):
            # delete the port binding and read it with the new rules
            if ext_sg.SECURITYGROUPS in port['port']:
                port['port'][ext_sg.SECURITYGROUPS] = (
                    self._get_security_groups_on_port(context, port))
                self._delete_port_security_group_bindings(context, port_id)
                self._process_port_create_security_group(
                    context,
                    port_id,
                    port['port'][ext_sg.SECURITYGROUPS])
                port_updated = True

            port = super(BrocadePluginV2, self).update_port(
                context, port_id, port)
            self._extend_port_dict_security_group(context, port)

        if original_port['admin_state_up'] != port['admin_state_up']:
            port_updated = True

        if (original_port['fixed_ips'] != port['fixed_ips'] or
            not utils.compare_elements(
                original_port.get(ext_sg.SECURITYGROUPS),
                port.get(ext_sg.SECURITYGROUPS))):
            self.notifier.security_groups_member_updated(
                context, port.get(ext_sg.SECURITYGROUPS))

        if port_updated:
            self._notify_port_updated(context, port)

        return self._extend_port_dict_binding(context, port)

    def get_port(self, context, port_id, fields=None):
        with context.session.begin(subtransactions=True):
            port = super(BrocadePluginV2, self).get_port(
                context, port_id, fields)
            self._extend_port_dict_security_group(context, port)
            self._extend_port_dict_binding(context, port)

        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        res_ports = []
        with context.session.begin(subtransactions=True):
            ports = super(BrocadePluginV2, self).get_ports(context,
                                                           filters,
                                                           fields)
            for port in ports:
                self._extend_port_dict_security_group(context, port)
                self._extend_port_dict_binding(context, port)
                res_ports.append(self._fields(port, fields))

        return res_ports

    def _notify_port_updated(self, context, port):
        port_id = port['id']
        bport = brocade_db.get_port(context, port_id)
        self.notifier.port_update(context, port,
                                  bport.physical_interface,
                                  bport.vlan_id)

    def _extend_port_dict_binding(self, context, port):
        if self._check_view_auth(context, port, self.binding_view):
            port[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_BRIDGE
            port['binding:vif_type'] = portbindings.VIF_TYPE_BRIDGE
            port[portbindings.CAPABILITIES] = {
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}
        return port

    def _check_view_auth(self, context, resource, action):
        return policy.check(context, action, resource)

    def get_plugin_version(self):
        """Get version number of the plugin."""
        return PLUGIN_VERSION

    @staticmethod
    def mac_reformat_62to34(interface_mac):
        """Transform MAC address format.

        Transforms from 6 groups of 2 hexadecimal numbers delimited by ":"
        to 3 groups of 4 hexadecimals numbers delimited by ".".

        :param interface_mac: MAC address in the format xx:xx:xx:xx:xx:xx
        :type interface_mac: string
        :returns: MAC address in the format xxxx.xxxx.xxxx
        :rtype: string

        """

        mac = interface_mac.replace(":", "")
        mac = mac[0:4] + "." + mac[4:8] + "." + mac[8:12]
        return mac
