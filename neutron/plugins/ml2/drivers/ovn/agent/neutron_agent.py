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
import copy
import datetime

from oslo_config import cfg
from oslo_utils import timeutils

from neutron._i18n import _
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.common import utils


class DeletedChassis(object):
    external_ids = {}
    hostname = '("Chassis" register deleted)'
    name = '("Chassis" register deleted)'


class NeutronAgent(abc.ABC):
    types = {}

    def __init_subclass__(cls):
        # Register the subclasses to be looked up by their type
        NeutronAgent.types[cls.agent_type] = cls

    def __init__(self, chassis_private, driver):
        self.driver = driver
        self.set_down = False
        self.update(chassis_private)

    def update(self, chassis_private, clear_down=False):
        self.chassis_private = chassis_private
        # When use the Chassis_Private table for agents health check,
        # chassis_private has attribute nb_cfg_timestamp.
        # nb_cfg_timestamp: the timestamp when ovn-controller finishes
        # processing the change corresponding to nb_cfg(
        # https://www.ovn.org/support/dist-docs/ovn-sb.5.html).
        # it can better reflect the status of chassis.
        # nb_cfg_timestamp is milliseconds, need to convert to datetime.
        if hasattr(chassis_private, 'nb_cfg_timestamp'):
            updated_at = datetime.datetime.fromtimestamp(
                chassis_private.nb_cfg_timestamp / 1000,
                datetime.timezone.utc)
        else:
            updated_at = timeutils.utcnow(with_timezone=True)
        self.updated_at = updated_at
        if clear_down:
            self.set_down = False

    @staticmethod
    def chassis_from_private(chassis_private):
        try:
            return chassis_private.chassis[0]
        except AttributeError:
            # No Chassis_Private support, just use Chassis
            return chassis_private
        except IndexError:
            # Chassis register has been deleted but not Chassis_Private.
            return DeletedChassis

    @property
    def chassis(self):
        return self.chassis_from_private(self.chassis_private)

    def as_dict(self):
        return {
            'binary': self.binary,
            'host': self.chassis.hostname,
            'heartbeat_timestamp': timeutils.normalize_time(
                self.updated_at.replace(microsecond=0)),
            'availability_zone': ', '.join(
                ovn_utils.get_chassis_availability_zones(self.chassis)),
            'topic': 'n/a',
            'description': self.description,
            'configurations': {
                'chassis_name': self.chassis.name,
                'bridge-mappings':
                    ovn_utils.get_ovn_chassis_other_config(self.chassis).get(
                        'ovn-bridge-mappings', '')},
            'start_flag': True,
            'agent_type': self.agent_type,
            'id': self.agent_id,
            'alive': self.alive,
            'admin_state_up': True}

    @property
    def alive(self):
        if self.set_down:
            return False
        # TODO(twilson) Determine if we can go back to just checking:
        # if self.driver.nb_ovn.nb_global.nb_cfg == self.nb_cfg:
        if self.driver.nb_ovn.nb_global.nb_cfg - self.nb_cfg <= 1:
            return True
        now = timeutils.utcnow(with_timezone=True)
        if (now - self.updated_at).total_seconds() < cfg.CONF.agent_down_time:
            # down, but not yet timed out
            return True
        return False

    @classmethod
    def from_type(cls, _type, chassis_private, driver):
        return cls.types[_type](chassis_private, driver)

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
    def nb_cfg(self):
        pass

    @property
    @abc.abstractmethod
    def agent_id(self):
        pass


class ControllerAgent(NeutronAgent):
    agent_type = ovn_const.OVN_CONTROLLER_AGENT
    binary = 'ovn-controller'

    @staticmethod  # it is by default, but this makes pep8 happy
    def __new__(cls, chassis_private, driver):
        _chassis = cls.chassis_from_private(chassis_private)
        other_config = ovn_utils.get_ovn_chassis_other_config(_chassis)
        if 'enable-chassis-as-gw' in other_config.get('ovn-cms-options', []):
            cls = ControllerGatewayAgent
        return super().__new__(cls)

    @staticmethod
    def id_from_chassis_private(chassis_private):
        return chassis_private.name

    @property
    def nb_cfg(self):
        return self.chassis_private.nb_cfg

    @property
    def agent_id(self):
        return self.id_from_chassis_private(self.chassis_private)

    @property
    def description(self):
        return self.chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_DESC_KEY, '')

    def update(self, chassis_private, clear_down=False):
        super().update(chassis_private, clear_down)
        _chassis = self.chassis_from_private(chassis_private)
        other_config = ovn_utils.get_ovn_chassis_other_config(_chassis)
        if 'enable-chassis-as-gw' in other_config.get('ovn-cms-options', []):
            self.__class__ = ControllerGatewayAgent


class ControllerGatewayAgent(ControllerAgent):
    agent_type = ovn_const.OVN_CONTROLLER_GW_AGENT

    def update(self, chassis_private, clear_down=False):
        super().update(chassis_private, clear_down)
        _chassis = self.chassis_from_private(chassis_private)
        other_config = ovn_utils.get_ovn_chassis_other_config(_chassis)
        if ('enable-chassis-as-gw' not in
                other_config.get('ovn-cms-options', [])):
            self.__class__ = ControllerAgent


class MetadataAgent(NeutronAgent):
    agent_type = ovn_const.OVN_METADATA_AGENT
    binary = 'neutron-ovn-metadata-agent'

    @property
    def alive(self):
        # If ovn-controller is down, then metadata agent is down even
        # if the metadata-agent binary is updating external_ids.
        try:
            if not AgentCache()[self.chassis_private.name].alive:
                return False
        except KeyError:
            return False
        return super().alive

    @property
    def nb_cfg(self):
        return int(self.chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY, 0))

    @staticmethod
    def id_from_chassis_private(chassis_private):
        return chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_METADATA_ID_KEY)

    @property
    def agent_id(self):
        return self.id_from_chassis_private(self.chassis_private)

    @property
    def description(self):
        return self.chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_METADATA_DESC_KEY, '')


class OVNNeutronAgent(NeutronAgent):
    agent_type = ovn_const.OVN_NEUTRON_AGENT
    binary = 'neutron-ovn-agent'

    @property
    def alive(self):
        # If ovn-controller is down, then OVN Neutron Agent is down even
        # if the neutron-ovn-agent binary is updating external_ids.
        try:
            if not AgentCache()[self.chassis_private.name].alive:
                return False
        except KeyError:
            return False
        return super().alive

    @property
    def nb_cfg(self):
        return int(self.chassis_private.external_ids.get(
            ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY, 0))

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


@utils.SingletonDecorator
class AgentCache:
    def __init__(self, driver=None):
        # This is just to make pylint happy because it doesn't like calls to
        # AgentCache() with no arguments, despite init only being called the
        # first time--and we do really want a driver passed in.
        if driver is None:
            raise ValueError(_("driver cannot be None"))
        self.agents = {}
        self.driver = driver

    def __iter__(self):
        # Copying self.agents will avoid any issue during the iteration if an
        # agent is added or deleted.
        _agents = copy.copy(self.agents)
        return iter(_agents.values())

    def __getitem__(self, key):
        return self.agents[key]

    def update(self, agent_type, row, clear_down=False):
        cls = NeutronAgent.types[agent_type]
        try:
            agent = self.agents[cls.id_from_chassis_private(row)]
            agent.update(row, clear_down=clear_down)
        except KeyError:
            agent = NeutronAgent.from_type(agent_type, row, self.driver)
            self.agents[agent.agent_id] = agent
        return agent

    def __delitem__(self, agent_id):
        del self.agents[agent_id]

    def agents_by_chassis_private(self, chassis_private):
        # Get unique agent ids based on the chassis_private
        agent_ids = {cls.id_from_chassis_private(chassis_private)
                     for cls in NeutronAgent.types.values()}
        # Return the cached agents of agent_ids whose keys are in the cache
        return (agent for agent in self if agent.agent_id in agent_ids)

    def get_agents(self, filters=None):
        filters = filters or {}
        agent_list = []
        for agent in self:
            agent_dict = agent.as_dict()
            if all(agent_dict[k] in v for k, v in filters.items()):
                agent_list.append(agent)
        return agent_list
