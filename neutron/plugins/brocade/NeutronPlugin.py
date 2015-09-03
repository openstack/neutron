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
# (Some parts adapted from LinuxBridge Plugin)
# TODO(shiv) need support for security groups


"""Implentation of Brocade Neutron Plugin."""

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import importutils

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import l3_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.rpc.handlers import securitygroups_rpc
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron import context as n_context
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import portbindings_base
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import portbindings
from neutron.extensions import securitygroup as ext_sg
from neutron.i18n import _LE, _LI
from neutron.plugins.brocade.db import models as brocade_db
from neutron.plugins.brocade import vlanbm as vbm
from neutron.plugins.common import constants as svc_constants


LOG = logging.getLogger(__name__)
AGENT_OWNER_PREFIX = "network:"
NOS_DRIVER = 'neutron.plugins.brocade.nos.nosdriver.NOSdriver'

SWITCH_OPTS = [cfg.StrOpt('address', default='',
                          help=_('The address of the host to SSH to')),
               cfg.StrOpt('username', default='',
                          help=_('The SSH username to use')),
               cfg.StrOpt('password', default='', secret=True,
                          help=_('The SSH password to use')),
               cfg.StrOpt('ostype', default='NOS',
                          help=_('Currently unused'))
               ]

PHYSICAL_INTERFACE_OPTS = [cfg.StrOpt('physical_interface', default='eth0',
                           help=_('The network interface to use when creating '
                                  'a port'))
                           ]

cfg.CONF.register_opts(SWITCH_OPTS, "SWITCH")
cfg.CONF.register_opts(PHYSICAL_INTERFACE_OPTS, "PHYSICAL_INTERFACE")


class BridgeRpcCallbacks(object):
    """Agent callback."""

    target = oslo_messaging.Target(version='1.2')
    # Device names start with "tap"
    # history
    #   1.1 Support Security Group RPC
    #   1.2 Support get_devices_details_list

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details."""

        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug("Device %(device)s details requested from %(agent_id)s",
                  {'device': device, 'agent_id': agent_id})
        port = brocade_db.get_port(rpc_context,
                                   device[len(n_const.TAP_DEVICE_PREFIX):])
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
            LOG.debug("%s can not be found in database", device)
        return entry

    def get_devices_details_list(self, rpc_context, **kwargs):
        return [
            self.get_device_details(
                rpc_context,
                device=device,
                **kwargs
            )
            for device in kwargs.pop('devices', [])
        ]

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
            LOG.debug("%s can not be found in database", device)
        return entry


class SecurityGroupServerRpcMixin(sg_db_rpc.SecurityGroupServerRpcMixin):

    @classmethod
    def get_port_from_device(cls, device):
        """Get port from the brocade specific db."""

        # TODO(shh) context is not being passed as
        # an argument to this function;
        #
        # need to be fixed in:
        # file: neutron/db/securtygroups_rpc_base.py
        # function: securitygroup_rules_for_devices()
        # which needs to pass context to us

        # Doing what other plugins are doing
        session = db.get_session()
        port = brocade_db.get_port_from_device(
            session, device[len(n_const.TAP_DEVICE_PREFIX):])

        # TODO(shiv): need to extend the db model to include device owners
        # make it appears that the device owner is of type network
        if port:
            port['device'] = device
            port['device_owner'] = AGENT_OWNER_PREFIX
            port['binding:vif_type'] = 'bridge'
        return port


class AgentNotifierApi(sg_rpc.SecurityGroupAgentRpcApiMixin):
    """Agent side of the linux bridge rpc API.

    API version history:
        1.0 - Initial version.
        1.1 - Added get_active_networks_info, create_dhcp_port,
              and update_dhcp_port methods.

    """

    def __init__(self, topic):
        self.topic = topic
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)
        self.topic_network_delete = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.DELETE)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)

    def network_delete(self, context, network_id):
        cctxt = self.client.prepare(topic=self.topic_network_delete,
                                    fanout=True)
        cctxt.cast(context, 'network_delete', network_id=network_id)

    def port_update(self, context, port, physical_network, vlan_id):
        cctxt = self.client.prepare(topic=self.topic_port_update, fanout=True)
        cctxt.cast(context, 'port_update', port=port,
                   physical_network=physical_network, vlan_id=vlan_id)


class BrocadePluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                      external_net_db.External_net_db_mixin,
                      extraroute_db.ExtraRoute_db_mixin,
                      SecurityGroupServerRpcMixin,
                      l3_agentschedulers_db.L3AgentSchedulerDbMixin,
                      agentschedulers_db.DhcpAgentSchedulerDbMixin,
                      portbindings_base.PortBindingBaseMixin):
    """BrocadePluginV2 is a Neutron plugin.

    Provides L2 Virtual Network functionality using VDX. Upper
    layer driver class that interfaces to NETCONF layer below.

    """

    def __init__(self):
        """Initialize Brocade Plugin.

        Specify switch address and db configuration.
        """

        super(BrocadePluginV2, self).__init__()
        self.supported_extension_aliases = ["binding", "security-group",
                                            "external-net", "router",
                                            "extraroute", "agent",
                                            "l3_agent_scheduler",
                                            "dhcp_agent_scheduler"]

        self.physical_interface = (cfg.CONF.PHYSICAL_INTERFACE.
                                   physical_interface)
        self.base_binding_dict = self._get_base_binding_dict()
        portbindings_base.register_port_dict_function()
        self.ctxt = n_context.get_admin_context()
        self._vlan_bitmap = vbm.VlanBitmap(self.ctxt)
        self._setup_rpc()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver
        )
        self.brocade_init()
        self.start_periodic_dhcp_agent_status_check()

    def brocade_init(self):
        """Brocade specific initialization."""

        self._switch = {'address': cfg.CONF.SWITCH.address,
                        'username': cfg.CONF.SWITCH.username,
                        'password': cfg.CONF.SWITCH.password
                        }
        self._driver = importutils.import_object(NOS_DRIVER)

    def _setup_rpc(self):
        # RPC support
        self.service_topics = {svc_constants.CORE: topics.PLUGIN,
                               svc_constants.L3_ROUTER_NAT: topics.L3PLUGIN}
        self.rpc_context = n_context.ContextBase('neutron', 'neutron',
                                                 is_admin=False)
        self.conn = n_rpc.create_connection(new=True)
        self.endpoints = [BridgeRpcCallbacks(),
                          securitygroups_rpc.SecurityGroupServerRpcCallback(),
                          dhcp_rpc.DhcpRpcCallback(),
                          l3_rpc.L3RpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]
        for svc_topic in self.service_topics.values():
            self.conn.create_consumer(svc_topic, self.endpoints, fanout=False)
        # Consume from all consumers in threads
        self.conn.consume_in_threads()
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.agent_notifiers[n_const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )
        self.agent_notifiers[n_const.AGENT_TYPE_L3] = (
            l3_rpc_agent_api.L3AgentNotifyAPI()
        )

    def create_network(self, context, network):
        """Create network.

        This call to create network translates to creation of port-profile on
        the physical switch.
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
            except Exception:
                # Proper formatting
                LOG.exception(_LE("Brocade NOS driver error"))
                LOG.debug("Returning the allocated vlan (%d) to the pool",
                          vlan_id)
                self._vlan_bitmap.release_vlan(int(vlan_id))
                raise Exception(_("Brocade plugin raised exception, "
                                  "check logs"))

            brocade_db.create_network(context, net_uuid, vlan_id)
            self._process_l3_create(context, net, network['network'])

        LOG.info(_LI("Allocated vlan (%d) from the pool"), vlan_id)
        return net

    def delete_network(self, context, net_id):
        """Delete network.

        This call to delete the network translates to removing the
        port-profile on the physical switch.
        """

        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, net_id)
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
                                            vlan_id)
            except Exception:
                # Proper formatting
                LOG.exception(_LE("Brocade NOS driver error"))
                raise Exception(_("Brocade plugin raised exception, "
                                  "check logs"))

            # now ok to delete the network
            brocade_db.delete_network(context, net_id)

        # relinquish vlan in bitmap
        self._vlan_bitmap.release_vlan(int(vlan_id))
        return result

    def update_network(self, context, id, network):

        session = context.session
        with session.begin(subtransactions=True):
            net = super(BrocadePluginV2, self).update_network(context, id,
                                                              network)
            self._process_l3_update(context, net, network['network'])
        return net

    def create_port(self, context, port):
        """Create logical port on the switch."""

        tenant_id = port['port']['tenant_id']
        network_id = port['port']['network_id']
        admin_state_up = port['port']['admin_state_up']

        physical_interface = self.physical_interface

        with context.session.begin(subtransactions=True):
            bnet = brocade_db.get_network(context, network_id)
            vlan_id = bnet['vlan']

            neutron_port = super(BrocadePluginV2, self).create_port(context,
                                                                    port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         neutron_port)
            interface_mac = neutron_port['mac_address']
            port_id = neutron_port['id']

            switch = self._switch

            # convert mac format: xx:xx:xx:xx:xx:xx -> xxxx.xxxx.xxxx
            mac = self.mac_reformat_62to34(interface_mac)
            try:
                self._driver.associate_mac_to_network(switch['address'],
                                                      switch['username'],
                                                      switch['password'],
                                                      vlan_id,
                                                      mac)
            except Exception:
                # Proper formatting
                LOG.exception(_LE("Brocade NOS driver error"))
                raise Exception(_("Brocade plugin raised exception, "
                                  "check logs"))

            # save to brocade persistent db
            brocade_db.create_port(context, port_id, network_id,
                                   physical_interface,
                                   vlan_id, tenant_id, admin_state_up)

        # apply any extensions
        return neutron_port

    def delete_port(self, context, port_id):
        with context.session.begin(subtransactions=True):
            neutron_port = self.get_port(context, port_id)
            interface_mac = neutron_port['mac_address']
            # convert mac format: xx:xx:xx:xx:xx:xx -> xxxx.xxxx.xxxx
            mac = self.mac_reformat_62to34(interface_mac)

            brocade_port = brocade_db.get_port(context, port_id)
            vlan_id = brocade_port['vlan_id']

            switch = self._switch
            try:
                self._driver.dissociate_mac_from_network(switch['address'],
                                                         switch['username'],
                                                         switch['password'],
                                                         vlan_id,
                                                         mac)
            except Exception:
                LOG.exception(_LE("Brocade NOS driver error"))
                raise Exception(
                    _("Brocade plugin raised exception, check logs"))

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
                # process_port_create_security_group also needs port id
                port['port']['id'] = port_id
                self._process_port_create_security_group(
                    context,
                    port['port'],
                    port['port'][ext_sg.SECURITYGROUPS])
                port_updated = True
            port_data = port['port']
            port = super(BrocadePluginV2, self).update_port(
                context, port_id, port)
            self._process_portbindings_create_and_update(context,
                                                         port_data,
                                                         port)
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

        return port

    def _notify_port_updated(self, context, port):
        port_id = port['id']
        bport = brocade_db.get_port(context, port_id)
        self.notifier.port_update(context, port,
                                  bport.physical_interface,
                                  bport.vlan_id)

    def _get_base_binding_dict(self):
        binding = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_BRIDGE,
            portbindings.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        return binding

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
