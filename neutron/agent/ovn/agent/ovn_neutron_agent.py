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

import uuid

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

    def run(self, event, row, old):
        ext_ids = {ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY: str(row.nb_cfg)}
        self.ovn_agent.sb_idl.db_set('Chassis_Private', self.ovn_agent.chassis,
                                     ('external_ids', ext_ids)).execute()


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
        events = [SbGlobalUpdateEvent]
        tables = ['SB_Global', 'Chassis_Private']
        for extension in self.ext_manager:
            events += extension.obj.sb_idl_events
            tables += extension.obj.sb_idl_tables

        events = [e(self) for e in set(events)]
        tables = set(tables)
        return ovsdb.MonitorAgentOvnSbIdl(tables, events,
                                          chassis=self.chassis).start()

    def start(self):
        self.ext_manager_api.ovs_idl = self._load_ovs_idl()
        self.load_config()
        # Before executing "_load_sb_idl", is is needed to execute
        # "load_config" to populate self.chassis.
        self.ext_manager_api.sb_idl = self._load_sb_idl()
        self.ext_manager_api.nb_idl = self._load_nb_idl()
        self.ext_manager.start()
        LOG.info('OVN Neutron Agent started')

    def stop(self, graceful=True):
        LOG.info('Stopping OVN Neutron Agent')
        super().stop(graceful)
