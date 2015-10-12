# Copyright 2015 Mellanox Technologies, Ltd
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

from oslo_log import log as logging

from neutron.agent.l2.extensions import qos
from neutron.i18n import _LE, _LI
from neutron.plugins.ml2.drivers.mech_sriov.agent.common import (
    exceptions as exc)
from neutron.plugins.ml2.drivers.mech_sriov.agent import eswitch_manager as esm
from neutron.plugins.ml2.drivers.mech_sriov.mech_driver import (
    mech_driver)

LOG = logging.getLogger(__name__)


class QosSRIOVAgentDriver(qos.QosAgentDriver):

    SUPPORTED_RULES = (
        mech_driver.SriovNicSwitchMechanismDriver.supported_qos_rule_types)

    def __init__(self):
        super(QosSRIOVAgentDriver, self).__init__()
        self.eswitch_mgr = None

    def initialize(self):
        self.eswitch_mgr = esm.ESwitchManager()

    def create_bandwidth_limit(self, port, rule):
        self.update_bandwidth_limit(port, rule)

    def update_bandwidth_limit(self, port, rule):
        pci_slot = port['profile'].get('pci_slot')
        device = port['device']
        self._set_vf_max_rate(device, pci_slot, rule.max_kbps)

    def delete_bandwidth_limit(self, port):
        pci_slot = port['profile'].get('pci_slot')
        if port.get('device_owner') is None:
            self.eswitch_mgr.clear_max_rate(pci_slot)
        else:
            device = port['device']
            self._set_vf_max_rate(device, pci_slot)

    def _set_vf_max_rate(self, device, pci_slot, max_kbps=0):
        if self.eswitch_mgr.device_exists(device, pci_slot):
            try:
                self.eswitch_mgr.set_device_max_rate(
                    device, pci_slot, max_kbps)
            except exc.SriovNicError:
                LOG.exception(
                    _LE("Failed to set device %s max rate"), device)
        else:
            LOG.info(_LI("No device with MAC %s defined on agent."), device)
