# Copyright 2025 Red Hat, Inc.
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
import tempfile

from oslo_config import cfg
from oslo_utils import timeutils
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp import venv

from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.conf.services import bgp as bgp_config
from neutron.services.bgp import ovn as bgp_ovn
from neutron.tests.functional import base as n_base
from neutron.tests.functional.services.bgp import fixtures

idl_schema_map = {
    'OVN_Northbound': bgp_ovn.OvnNbIdl,
    'OVN_Southbound': bgp_ovn.OvnSbIdl,
}


class BaseBgpIDLTestCase(n_base.BaseLoggingTestCase):
    schemas = []

    def setUp(self):
        ovn_conf.register_opts()
        bgp_config.register_opts(cfg.CONF)
        super().setUp()
        self.setup_venv()
        self.create_idls()

    def create_connection(self, schema):
        idl = idl_schema_map[schema](self._schema_map[schema])
        return connection.Connection(idl, timeout=10)

    def setup_venv(self):
        ovsvenv = venv.OvsOvnVenvFixture(
            tempfile.mkdtemp(),
            ovsdir=os.getenv('OVS_SRCDIR'),
            ovndir=os.getenv('OVN_SRCDIR'),
            remove=True)

        self.useFixture(ovsvenv)

        self._schema_map = {
            'OVN_Northbound': ovsvenv.ovnnb_connection,
            'OVN_Southbound': ovsvenv.ovnsb_connection,
            'Open_vSwitch': ovsvenv.ovs_connection,
        }

    def create_idls(self):
        for schema in self.schemas:
            connection = self.create_connection(schema)
            if schema == 'OVN_Northbound':
                self.nb_api = self.useFixture(
                    fixtures.OvnNbIdlApiFixture(connection)).obj
            elif schema == 'OVN_Southbound':
                self.sb_api = self.useFixture(
                    fixtures.OvnSbIdlApiFixture(connection)).obj
            elif schema == 'Open_vSwitch':
                self.ovs_api = self.useFixture(
                    fixtures.OvsApiFixture(connection)).obj


class BaseBgpNbIdlTestCase(BaseBgpIDLTestCase):
    schemas = ['OVN_Northbound']


class BaseBgpSbIdlTestCase(BaseBgpIDLTestCase):
    schemas = ['OVN_Southbound']

    def setUp(self):
        bgp_ovn.OvnSbIdl.tables = ('Chassis', 'Encap', 'Chassis_Private')
        try:
            super().setUp()
        finally:
            bgp_ovn.OvnSbIdl.tables = bgp_ovn.OVN_SB_TABLES

    def add_fake_chassis(self, name, ip, external_ids=None):
        external_ids = external_ids or {}
        chassis = self.sb_api.chassis_add(
            name, ['geneve'], ip).execute(check_error=True)

        nb_cfg_timestamp = timeutils.utcnow_ts() * 1000
        self.sb_api.db_create(
            'Chassis_Private', name=name,
            chassis=chassis.uuid, nb_cfg_timestamp=nb_cfg_timestamp,
            external_ids=external_ids
        ).execute(check_error=True)

        return self.sb_api.db_list_rows(
            'Chassis_Private', [name]).execute(check_error=True)[0]


class BaseBgpTestCase(BaseBgpSbIdlTestCase):
    schemas = ['OVN_Northbound', 'OVN_Southbound']
