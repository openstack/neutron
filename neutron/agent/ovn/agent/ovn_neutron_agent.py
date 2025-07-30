# Copyright (c) 2023 Red Hat, Inc.
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

import secrets
import threading
import uuid

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service
from ovsdbapp.backend.ovs_idl import event as row_event

from neutron.agent.ovn.agent import ovsdb
from neutron.agent.ovn.extensions import extension_manager as ext_mgr
from neutron.common.ovn import constants as ovn_const


LOG = logging.getLogger(__name__)
OVN_MONITOR_UUID_NAMESPACE = uuid.UUID('fd7e0970-7164-11ed-80f0-00000003158a')


class SbGlobalUpdateEvent(row_event.RowEvent):
    """Row update event on SB_Global table.

    This event will trigger the OVN Neutron Agent update of the
    'neutron:ovn-neutron-agent-sb-cfg' key in 'SB_Global', that is used to
    determine the agent status.
    """

    def __init__(self, ovn_agent):
        self.ovn_agent = ovn_agent
        table = 'SB_Global'
        events = (self.ROW_UPDATE, )
        super().__init__(events, table, None)
        self.event_name = self.__class__.__name__
        self._first_run = True

    def run(self, event, row, old):
        def _update_chassis(self, row):
            self.ovn_agent.update_neutron_sb_cfg_key(nb_cfg=row.nb_cfg)

        delay = 0
        if self._first_run:
            self._first_run = False
        else:
            # We occasionally see port binding failed errors due to
            # the ML2 driver refusing to bind the port to a dead agent.
            # If all agents heartbeat at the same time, they will all
            # cause a load spike on the server. To mitigate that it is needed
            # to spread out the load by introducing a random delay.
            max_delay = max(min(cfg.CONF.agent_down_time // 3, 10), 3)
            delay = secrets.SystemRandom().randint(0, max_delay)

        LOG.debug('Delaying updating chassis table for %s seconds', delay)
        timer = threading.Timer(delay, _update_chassis, [self, row])
        timer.start()


class ChassisPrivateCreateEvent(row_event.RowEvent):
    """Row create event - Chassis name == our_chassis.

    On connection, we get a dump of all chassis so if we catch a creation
    of our own chassis it has to be a reconnection. In this case, we need
    to do a full sync to make sure that we capture all changes while the
    connection to OVSDB was down.
    """
    def __init__(self, ovn_agent):
        self._first_time = True
        self.ovn_agent = ovn_agent
        events = (self.ROW_CREATE,)
        super().__init__(events, 'Chassis_Private', None)
        self.conditions = (('name', '=', self.ovn_agent.chassis),)
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        if self._first_time:
            self._first_time = False
            return

        # Re-register the OVN agent with the local chassis in case its
        # entry was re-created (happens when restarting the ovn-controller)
        self.ovn_agent.register_ovn_agent()
        self.ovn_agent.update_neutron_sb_cfg_key()


class OVNNeutronAgent(service.Service):

    def __init__(self, conf):
        super().__init__()
        self._conf = conf
        self._chassis = None
        self._chassis_id = None
        self._ovn_bridge = None
        self.ext_manager_api = ext_mgr.OVNAgentExtensionAPI()
        self.ext_manager = ext_mgr.OVNAgentExtensionManager(self._conf)
        self.ext_manager.initialize(None, 'ovn', self)

    def __getitem__(self, name):
        """Return the named extension objet from ``self.ext_manager``"""
        return self.ext_manager[name].obj

    @property
    def conf(self):
        return self._conf

    @property
    def ovs_idl(self):
        if not self.ext_manager_api.ovs_idl:
            self.ext_manager_api.ovs_idl = self._load_ovs_idl()
        return self.ext_manager_api.ovs_idl

    @property
    def nb_idl(self):
        return self.ext_manager_api.nb_idl

    @property
    def nb_post_fork_event(self):
        return self.ext_manager_api.nb_post_fork_event

    @property
    def sb_idl(self):
        return self.ext_manager_api.sb_idl

    @property
    def sb_post_fork_event(self):
        return self.ext_manager_api.sb_post_fork_event

    @property
    def chassis(self):
        return self._chassis

    @property
    def chassis_id(self):
        return self._chassis_id

    @property
    def ovn_bridge(self):
        return self._ovn_bridge

    def load_config(self):
        self._chassis = ovsdb.get_own_chassis_name(self.ovs_idl)
        try:
            self._chassis_id = uuid.UUID(self.chassis)
        except ValueError:
            # OVS system-id could be a non UUID formatted string.
            self._chassis_id = uuid.uuid5(OVN_MONITOR_UUID_NAMESPACE,
                                          self._chassis)
        self._ovn_bridge = ovsdb.get_ovn_bridge(self.ovs_idl)
        LOG.info("Loaded chassis name %s (UUID: %s) and ovn bridge %s.",
                 self.chassis, self.chassis_id, self.ovn_bridge)

    def _load_ovs_idl(self):
        events = []
        for extension in self.ext_manager:
            events += extension.obj.ovs_idl_events
        events = [e(self) for e in set(events)]
        return ovsdb.MonitorAgentOvsIdl(set(events)).start()

    def _load_nb_idl(self):
        events = []
        tables = []
        for extension in self.ext_manager:
            events += extension.obj.nb_idl_events
            tables += extension.obj.nb_idl_tables

        if not (tables or events):
            # If there is no need to retrieve any table nor attend to any
            # event, the IDL object is not created to save a DB connection.
            return None

        events = [e(self) for e in set(events)]
        tables = set(tables)
        return ovsdb.MonitorAgentOvnNbIdl(tables, events).start()

    def _load_sb_idl(self):
        events = [SbGlobalUpdateEvent,
                  ChassisPrivateCreateEvent,
                  ]
        tables = ['SB_Global', 'Chassis_Private']
        for extension in self.ext_manager:
            events += extension.obj.sb_idl_events
            tables += extension.obj.sb_idl_tables

        events = [e(self) for e in set(events)]
        tables = set(tables)
        return ovsdb.MonitorAgentOvnSbIdl(tables, events,
                                          chassis=self.chassis).start()

    def register_ovn_agent(self):
        # NOTE(lucasagomes): db_add() will not overwrite the UUID if
        # it's already set.
        # Generate unique, but consistent ovn agent id for chassis name
        agent_id = uuid.uuid5(self.chassis_id, 'ovn_agent')
        ext_ids = {ovn_const.OVN_AGENT_NEUTRON_ID_KEY: str(agent_id)}
        self.sb_idl.db_add('Chassis_Private', self.chassis, 'external_ids',
                           ext_ids).execute(check_error=True)

    def _cleanup_previous_tags(self):
        """Remove any existing tag related to the OVN Metadata agent

        The OVN Metadata agent is deprecated and marked for removal in 2026.2.
        This code should stay during the following SLURP release (2027.1) and
        be removed in the next release (2027.2).

        While both agents can provide the same functionality (OVN Metadata
        agent and OVN agent with the metadata extension), it is needed to
        provide a cleanup method for any leftover tag from the other agent.
        """
        metadata_keys = (ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY,
                         ovn_const.OVN_AGENT_METADATA_DESC_KEY,
                         ovn_const.OVN_AGENT_METADATA_ID_KEY)
        self.sb_idl.db_remove(
            'Chassis_Private', self.chassis, 'external_ids',
            *metadata_keys, if_exists=True).execute(check_error=True)

    def update_neutron_sb_cfg_key(self, nb_cfg=None):
        nb_cfg = (nb_cfg or
                  self.sb_idl.db_get('Chassis_Private',
                                     self.chassis, 'nb_cfg').execute())
        external_ids = {ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY: str(nb_cfg)}
        self.sb_idl.db_set(
            'Chassis_Private', self.chassis,
            ('external_ids', external_ids)).execute(check_error=True)

    def start(self):
        self.ext_manager_api.ovs_idl = self._load_ovs_idl()
        self.load_config()
        # Before executing "_load_sb_idl", is is needed to execute
        # "load_config" to populate self.chassis.
        self.ext_manager_api.sb_idl = self._load_sb_idl()
        self.ext_manager_api.nb_idl = self._load_nb_idl()
        self.ext_manager.start()

        self._cleanup_previous_tags()
        self.register_ovn_agent()
        self.update_neutron_sb_cfg_key()
        LOG.info('OVN Neutron Agent started')

    def stop(self, graceful=True):
        LOG.info('Stopping OVN Neutron Agent')
        super().stop(graceful)
