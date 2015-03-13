# Copyright 2014 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from oslo_config import cfg
from oslo_log import log

from neutron.common import constants
from neutron.extensions import portbindings
from neutron.i18n import _LE, _LW
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.mech_sriov import exceptions as exc


LOG = log.getLogger(__name__)
FLAT_VLAN = 0

sriov_opts = [
    cfg.ListOpt('supported_pci_vendor_devs',
               default=['15b3:1004', '8086:10ca'],
               help=_("Supported PCI vendor devices, defined by "
                      "vendor_id:product_id according to the PCI ID "
                      "Repository. Default enables support for Intel "
                      "and Mellanox SR-IOV capable NICs")),
    cfg.BoolOpt('agent_required',
                default=False,
                help=_("SRIOV neutron agent is required for port binding")),

]

cfg.CONF.register_opts(sriov_opts, "ml2_sriov")


class SriovNicSwitchMechanismDriver(api.MechanismDriver):
    """Mechanism Driver for SR-IOV capable NIC based switching.

    The SriovNicSwitchMechanismDriver integrates the ml2 plugin with the
    sriovNicSwitch L2 agent depending on configuration option.
    Port binding with this driver may require the sriovNicSwitch agent
    to be running on the port's host, and that agent to have connectivity
    to at least one segment of the port's network.
    L2 agent is not essential for port binding; port binding is handled by
    VIF Driver via libvirt domain XML.
    L2 Agent presents in  order to manage port update events.
    If vendor NIC does not support updates, setting agent_required = False
    will allow to use Mechanism Driver without L2 agent.

    """

    def __init__(self,
                 agent_type=constants.AGENT_TYPE_NIC_SWITCH,
                 vif_type=portbindings.VIF_TYPE_HW_VEB,
                 vif_details={portbindings.CAP_PORT_FILTER: False},
                 supported_vnic_types=[portbindings.VNIC_DIRECT,
                                       portbindings.VNIC_MACVTAP],
                 supported_pci_vendor_info=None):
        """Initialize base class for SriovNicSwitch L2 agent type.

        :param agent_type: Constant identifying agent type in agents_db
        :param vif_type: Value for binding:vif_type when bound
        :param vif_details: Dictionary with details for VIF driver when bound
        :param supported_vnic_types: The binding:vnic_type values we can bind
        :param supported_pci_vendor_info: The pci_vendor_info values to bind
        """
        self.agent_type = agent_type
        self.supported_vnic_types = supported_vnic_types
        self.vif_type = vif_type
        self.vif_details = vif_details
        self.supported_network_types = (p_const.TYPE_VLAN, p_const.TYPE_FLAT)

    def initialize(self):
        try:
            self.pci_vendor_info = self._parse_pci_vendor_config(
                        cfg.CONF.ml2_sriov.supported_pci_vendor_devs)
            self.agent_required = cfg.CONF.ml2_sriov.agent_required
        except ValueError:
            LOG.exception(_LE("Failed to parse supported PCI vendor devices"))
            raise cfg.Error(_("Parsing supported pci_vendor_devs failed"))

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        if not self._check_supported_pci_vendor_device(context):
            LOG.debug("Refusing to bind due to unsupported pci_vendor device")
            return

        if self.agent_required:
            for agent in context.host_agents(self.agent_type):
                LOG.debug("Checking agent: %s", agent)
                if agent['alive']:
                    if self.try_to_bind(context, agent):
                        return
                else:
                    LOG.warning(_LW("Attempting to bind with dead agent: %s"),
                                agent)
        else:
            self.try_to_bind(context)

    def try_to_bind(self, context, agent=None):
        for segment in context.segments_to_bind:
            if self.check_segment(segment, agent):
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self._get_vif_details(segment),
                                    constants.PORT_STATUS_ACTIVE)
                LOG.debug("Bound using segment: %s", segment)
                return True
        return False

    def check_segment(self, segment, agent=None):
        """Check if segment can be bound.

        :param segment: segment dictionary describing segment to bind
        :param agent: agents_db entry describing agent to bind or None
        :returns: True if segment can be bound for agent
        """
        network_type = segment[api.NETWORK_TYPE]
        if network_type in self.supported_network_types:
            if agent:
                mappings = agent['configurations'].get('device_mappings', {})
                LOG.debug("Checking segment: %(segment)s "
                          "for mappings: %(mappings)s ",
                          {'segment': segment, 'mappings': mappings})
                return segment[api.PHYSICAL_NETWORK] in mappings
            return True
        return False

    def _check_supported_pci_vendor_device(self, context):
        if self.pci_vendor_info:
            profile = context.current.get(portbindings.PROFILE, {})
            if not profile:
                LOG.debug("Missing profile in port binding")
                return False
            pci_vendor_info = profile.get('pci_vendor_info')
            if not pci_vendor_info:
                LOG.debug("Missing pci vendor info in profile")
                return False
            if pci_vendor_info not in self.pci_vendor_info:
                LOG.debug("Unsupported pci_vendor %s", pci_vendor_info)
                return False
            return True
        return False

    def _get_vif_details(self, segment):
        network_type = segment[api.NETWORK_TYPE]
        if network_type == p_const.TYPE_FLAT:
            vlan_id = FLAT_VLAN
        elif network_type == p_const.TYPE_VLAN:
            vlan_id = segment[api.SEGMENTATION_ID]
        else:
            raise exc.SriovUnsupportedNetworkType(net_type=network_type)
        vif_details = self.vif_details.copy()
        vif_details[portbindings.VIF_DETAILS_VLAN] = str(vlan_id)
        return vif_details

    def _parse_pci_vendor_config(self, pci_vendor_list):
        parsed_list = []
        for elem in pci_vendor_list:
            elem = elem.strip()
            if not elem:
                continue
            split_result = elem.split(':')
            if len(split_result) != 2:
                raise ValueError(_("Invalid pci_vendor_info: '%s'") % elem)
            vendor_id = split_result[0].strip()
            if not vendor_id:
                raise ValueError(_("Missing vendor_id in: '%s'") % elem)
            product_id = split_result[1].strip()
            if not product_id:
                raise ValueError(_("Missing product_id in: '%s'") % elem)
            parsed_list.append(elem)
        return parsed_list
