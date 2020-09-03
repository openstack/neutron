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

import abc

from oslo_utils import timeutils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils


class NeutronAgent(abc.ABC):
    types = {}

    def __init_subclass__(cls):
        # Register the subclasses to be looked up by their type
        NeutronAgent.types[cls.agent_type] = cls

    def __init__(self, chassis_private):
        self.chassis_private = chassis_private
        self.chassis = self.get_chassis(chassis_private)

    @staticmethod
    def get_chassis(chassis_private):
        try:
            return chassis_private.chassis[0]
        except (AttributeError, IndexError):
            # No Chassis_Private support, just use Chassis
            return chassis_private

    @property
    def updated_at(self):
        try:
            return timeutils.parse_isotime(self.chassis.external_ids[self.key])
        except KeyError:
            return timeutils.utcnow(with_timezone=True)

    def as_dict(self, alive):
        return {
            'binary': self.binary,
            'host': self.chassis.hostname,
            'heartbeat_timestamp': timeutils.utcnow(),
            'availability_zone': ', '.join(
                ovn_utils.get_chassis_availability_zones(self.chassis)),
            'topic': 'n/a',
            'description': self.description,
            'configurations': {
                'chassis_name': self.chassis.name,
                'bridge-mappings':
                    self.chassis.external_ids.get('ovn-bridge-mappings', '')},
            'start_flag': True,
            'agent_type': self.agent_type,
            'id': self.agent_id,
            'alive': alive,
            'admin_state_up': True}

    @classmethod
    def from_type(cls, _type, chassis_private):
        return cls.types[_type](chassis_private)

    @staticmethod
    def matches_chassis(chassis):
        """Is this Agent type found on the passed in chassis?"""
        return True

    @classmethod
    def agents_from_chassis(cls, chassis_private):
        return [AgentCls(chassis_private)
                for AgentCls in cls.types.values()
                if AgentCls.matches_chassis(cls.get_chassis(chassis_private))]

    @property
    @abc.abstractmethod
    def agent_type(self):
        pass


class ControllerAgent(NeutronAgent):
    agent_type = ovn_const.OVN_CONTROLLER_AGENT
    binary = 'ovn-controller'
    key = ovn_const.OVN_LIVENESS_CHECK_EXT_ID_KEY

    @staticmethod
    def matches_chassis(chassis):
        return ('enable-chassis-as-gw' not in
                chassis.external_ids.get('ovn-cms-options', []))

    @property
    def nb_cfg(self):
        return self.chassis_private.nb_cfg

    @property
    def agent_id(self):
        return self.chassis_private.name

    @property
    def description(self):
        return self.chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_DESC_KEY, '')


class ControllerGatewayAgent(ControllerAgent):
    agent_type = ovn_const.OVN_CONTROLLER_GW_AGENT

    @staticmethod
    def matches_chassis(chassis):
        return ('enable-chassis-as-gw' in
                chassis.external_ids.get('ovn-cms-options', []))


class MetadataAgent(NeutronAgent):
    agent_type = ovn_const.OVN_METADATA_AGENT
    binary = 'neutron-ovn-metadata-agent'
    key = ovn_const.METADATA_LIVENESS_CHECK_EXT_ID_KEY

    @property
    def nb_cfg(self):
        return int(self.chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY, 0))

    @property
    def agent_id(self):
        return self.chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_METADATA_ID_KEY)

    @property
    def description(self):
        return self.chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_METADATA_DESC_KEY, '')
