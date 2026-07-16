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

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils


class DeletedChassis:
    external_ids = {}
    other_config = {}
    hostname = '("Chassis" register deleted)'
    name = '("Chassis" register deleted)'


class NeutronAgent(abc.ABC):
    types = {}

    def __init_subclass__(cls):
        NeutronAgent.types[cls.agent_type] = cls

    def __init__(self, chassis_private):
        self.chassis_private = chassis_private

    @staticmethod
    def _get_chassis(chassis_private):
        try:
            return chassis_private.chassis[0]
        except IndexError:
            return DeletedChassis

    @property
    def chassis(self):
        return self._get_chassis(self.chassis_private)

    def agent_state(self):
        """Build the agent_state dict for create_or_update_agent()."""
        return {
            'binary': self.binary,
            'host': self.chassis.hostname,
            'availability_zone': ', '.join(
                ovn_utils.get_chassis_availability_zones(self.chassis)),
            'topic': 'n/a',
            'description': self.description,
            'configurations': {
                'chassis_name': self.chassis.name,
                'bridge-mappings':
                    ovn_utils.get_ovn_bridge_mappings(self.chassis)},
            'agent_type': self.agent_type,
            'id': self.agent_id,
        }

    @classmethod
    def from_type(cls, _type, chassis_private):
        return cls.types[_type](chassis_private)

    @property
    @abc.abstractmethod
    def agent_type(self):
        pass

    @property
    @abc.abstractmethod
    def binary(self):
        pass

    @property
    @abc.abstractmethod
    def agent_id(self):
        pass

    @property
    @abc.abstractmethod
    def description(self):
        pass


class ControllerAgent(NeutronAgent):
    agent_type = ovn_const.OVN_CONTROLLER_AGENT
    binary = 'ovn-controller'

    @staticmethod
    def __new__(cls, chassis_private):
        _chassis = cls._get_chassis(chassis_private)
        if ovn_utils.is_gateway_chassis(_chassis):
            cls = ControllerGatewayAgent
        return super().__new__(cls)

    @staticmethod
    def id_from_chassis_private(chassis_private):
        return chassis_private.name

    @property
    def agent_id(self):
        return self.id_from_chassis_private(self.chassis_private)

    @property
    def description(self):
        return self.chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_DESC_KEY, '')


class ControllerGatewayAgent(ControllerAgent):
    agent_type = ovn_const.OVN_CONTROLLER_GW_AGENT


class OVNNeutronAgent(NeutronAgent):
    agent_type = ovn_const.OVN_NEUTRON_AGENT
    binary = 'neutron-ovn-agent'

    @staticmethod
    def id_from_chassis_private(chassis_private):
        return chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_NEUTRON_ID_KEY)

    @property
    def agent_id(self):
        return self.id_from_chassis_private(self.chassis_private)

    @property
    def description(self):
        return self.chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_NEUTRON_DESC_KEY, '')
