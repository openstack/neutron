# Copyright (c) 2013 OpenStack Foundation
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

import os
import uuid

from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net
from neutron_lib.api.definitions import qinq as qinq_apidef
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants
from neutron_lib.plugins.ml2 import ovs_constants as ovs_const
from oslo_config import cfg
from oslo_log import log

from neutron._i18n import _
from neutron.agent import securitygroups_rpc
from neutron.conf.plugins.ml2.drivers.openvswitch import mech_ovs_conf
from neutron.plugins.ml2.drivers import mech_agent
from neutron.services.logapi.drivers.openvswitch import driver as log_driver
from neutron.services.qos.drivers.openvswitch import driver as ovs_qos_driver

LOG = log.getLogger(__name__)

IPTABLES_FW_DRIVER_FULL = ("neutron.agent.linux.iptables_firewall."
                           "OVSHybridIptablesFirewallDriver")

mech_ovs_conf.register_ovs_mech_driver_opts()


class OpenvswitchMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using openvswitch L2 agent.

    The OpenvswitchMechanismDriver integrates the ml2 plugin with the
    openvswitch L2 agent. Port binding with this driver requires the
    openvswitch agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """

    resource_provider_uuid5_namespace = uuid.UUID(
        '87ee7d5c-73bb-11e8-9008-c4d987b2a692')

    _explicitly_not_supported_extensions = set([
        vlan_apidef.ALIAS,
        qinq_apidef.ALIAS
    ])

    def __init__(self):
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        vif_details = {portbindings.CAP_PORT_FILTER: sg_enabled,
                       portbindings.VIF_DETAILS_CONNECTIVITY:
                           self.connectivity}
        # NOTE(moshele): Bind DIRECT (SR-IOV) port allows
        # to offload the OVS flows using tc to the SR-IOV NIC.
        # We are using OVS mechanism driver because the openvswitch (>=2.8.0)
        # support hardware offload via tc and that allow us to manage the VF by
        # OpenFlow control plane using representor net-device.
        supported_vnic_types = [portbindings.VNIC_NORMAL,
                                portbindings.VNIC_DIRECT,
                                portbindings.VNIC_SMARTNIC,
                                portbindings.VNIC_VHOST_VDPA,
                                ]
        prohibit_list = cfg.CONF.OVS_DRIVER.vnic_type_prohibit_list
        super().__init__(
            constants.AGENT_TYPE_OVS,
            portbindings.VIF_TYPE_OVS,
            vif_details,
            supported_vnic_types=supported_vnic_types,
            vnic_type_prohibit_list=prohibit_list)

        ovs_qos_driver.register()
        log_driver.register()

    @property
    def connectivity(self):
        return portbindings.CONNECTIVITY_L2

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [constants.TYPE_LOCAL, constants.TYPE_FLAT,
                 constants.TYPE_VLAN])

    def get_mappings(self, agent):
        return agent['configurations'].get('bridge_mappings', {})

    def get_standard_device_mappings(self, agent):
        """Return the agent's bridge mappings in a standard way.

        The common format for OVS and SRIOv mechanism drivers:
        {'physnet_name': ['device_or_bridge_1', 'device_or_bridge_2']}

        :param agent: The agent
        :returns A dict in the format: {'physnet_name': ['bridge_or_device']}
        :raises ValueError: if there is no bridge_mappings key in
                            agent['configurations']
        """
        if 'bridge_mappings' in agent['configurations']:
            return {k: [v] for k, v in
                    agent['configurations']['bridge_mappings'].items()}
        raise ValueError(
            _('Cannot standardize bridge mappings of agent type: %s'),
            agent['agent_type'])

    def bind_port(self, context):
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        profile = context.current.get(portbindings.PROFILE)
        capabilities = []
        if profile:
            capabilities = profile.get('capabilities', [])
        # TODO(sean-k-mooney): in the case of the Mellanox connectx6 dx and lx
        # nics vhost-vdpa is only supported in switchdev mode but that is not
        # strictly required by other vendors so we should ideally add a config
        # value to control checking of switchdev support per host via the
        # agent['configurations']
        if (vnic_type == portbindings.VNIC_DIRECT and
                'switchdev' not in capabilities):
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s with "
                      "no switchdev capability", portbindings.VNIC_DIRECT)
            return
        super().bind_port(context)

    def get_supported_vif_type(self, agent):
        caps = agent['configurations'].get('ovs_capabilities', {})
        if (any(x in caps.get('iface_types', []) for x
                in [ovs_const.OVS_DPDK_VHOST_USER,
                    ovs_const.OVS_DPDK_VHOST_USER_CLIENT]) and
                agent['configurations'].get('datapath_type') ==
                ovs_const.OVS_DATAPATH_NETDEV):
            return portbindings.VIF_TYPE_VHOST_USER
        return self.vif_type

    def get_vif_type(self, context, agent, segment):
        if (context.current.get(portbindings.VNIC_TYPE) ==
                portbindings.VNIC_DIRECT):
            return portbindings.VIF_TYPE_OVS
        return self.get_supported_vif_type(agent)

    def get_vhost_mode(self, iface_types):
        # NOTE(sean-k-mooney): this function converts the ovs vhost user
        # driver mode into the qemu vhost user mode. If OVS is the server,
        # qemu is the client and vice-versa.
        if (ovs_const.OVS_DPDK_VHOST_USER_CLIENT in iface_types):
            return portbindings.VHOST_USER_MODE_SERVER
        return portbindings.VHOST_USER_MODE_CLIENT

    def get_vif_details(self, context, agent, segment):
        vif_details = self._pre_get_vif_details(agent, context)
        self._set_bridge_name(context.current, vif_details, agent)
        return vif_details

    @staticmethod
    def _set_bridge_name(port, vif_details, agent):
        # REVISIT(rawlin): add BridgeName as a nullable column to the Port
        # model and simply check here if it's set and insert it into the
        # vif_details.

        def set_bridge_name_inner(bridge_name):
            vif_details[portbindings.VIF_DETAILS_BRIDGE_NAME] = bridge_name

        bridge_name = agent['configurations'].get('integration_bridge')
        if bridge_name:
            vif_details[portbindings.VIF_DETAILS_BRIDGE_NAME] = bridge_name

        registry.publish(
            ovs_const.OVS_BRIDGE_NAME, events.BEFORE_READ,
            set_bridge_name_inner,
            payload=events.EventPayload(None, metadata={'port': port}))

    def _pre_get_vif_details(self, agent, context):
        a_config = agent['configurations']
        vif_type = self.get_vif_type(context, agent, segment=None)
        if vif_type != portbindings.VIF_TYPE_VHOST_USER:
            details = {
                **self.vif_details,
                portbindings.OVS_HYBRID_PLUG: a_config.get(
                    portbindings.OVS_HYBRID_PLUG)}
        else:
            sock_path = self.agent_vhu_sockpath(agent, context.current['id'])
            caps = a_config.get('ovs_capabilities', {})
            mode = self.get_vhost_mode(caps.get('iface_types', []))
            details = {portbindings.CAP_PORT_FILTER: False,
                       portbindings.OVS_HYBRID_PLUG: False,
                       portbindings.VHOST_USER_MODE: mode,
                       portbindings.VHOST_USER_OVS_PLUG: True,
                       portbindings.VHOST_USER_SOCKET: sock_path}
        details[portbindings.OVS_DATAPATH_TYPE] = a_config.get(
            'datapath_type', ovs_const.OVS_DATAPATH_SYSTEM)
        return details

    @staticmethod
    def agent_vhu_sockpath(agent, port_id):
        """Return the agent's vhost-user socket path for a given port"""
        sockdir = agent['configurations'].get('vhostuser_socket_dir',
                                              ovs_const.VHOST_USER_SOCKET_DIR)
        sock_name = (constants.VHOST_USER_DEVICE_PREFIX + port_id)[:14]
        return os.path.join(sockdir, sock_name)

    @staticmethod
    def provider_network_attribute_updates_supported():
        return [provider_net.SEGMENTATION_ID]
