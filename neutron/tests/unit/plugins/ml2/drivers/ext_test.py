# Copyright 2015 Intel Corporation.
# Copyright 2015 Isaku Yamahata <isaku.yamahata at intel com>
#                               <isaku.yamahata at gmail com>
# All Rights Reserved.
#
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

from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib.db import model_base
from neutron_lib.plugins.ml2 import api
import oslo_db.sqlalchemy.session
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.api import extensions
from neutron.db import models_v2
from neutron.objects import subnet as subnet_obj
from neutron.tests.unit.plugins.ml2 import extensions as test_extensions


class TestExtensionDriverBase(api.ExtensionDriver):
    _supported_extension_aliases = 'fake_extension'

    def initialize(self):
        extensions.append_api_extensions_path(test_extensions.__path__)

    @property
    def extension_alias(self):
        return self._supported_extension_aliases


class TestExtensionDriver(TestExtensionDriverBase):
    def initialize(self):
        super().initialize()
        # keep track of values
        self.val_by_id = {}

    def _check_create(self, session, data, result):
        assert(isinstance(session, oslo_db.sqlalchemy.session.Session))
        assert(isinstance(data, dict))
        assert('id' not in data)
        assert(isinstance(result, dict))
        assert(result['id'] is not None)

    def _check_update(self, session, data, result):
        assert(isinstance(session, oslo_db.sqlalchemy.session.Session))
        assert(isinstance(data, dict))
        assert(isinstance(result, dict))
        assert(result['id'] is not None)

    def _check_extend(self, session, result, entry,
                      expected_db_entry_class, expected_obj_entry_class=None):
        # TODO(slaweq): After converting all code to use Subnet OVO,
        # expected_db_entry_class can be removed as only OVO object
        # should be expected here
        assert(isinstance(session, oslo_db.sqlalchemy.session.Session))
        assert(isinstance(result, dict))
        assert(result['id'] is not None)
        if expected_obj_entry_class:
            assert(
                isinstance(
                    entry, expected_db_entry_class | expected_obj_entry_class
                )
            )
        else:
            assert(isinstance(entry, expected_db_entry_class))
        assert(entry.id == result['id'])

    def _store_change(self, result, data, field):
        if field in data and data[field] != constants.ATTR_NOT_SPECIFIED:
            self.val_by_id[result['id']] = data[field]
        elif result['id'] not in self.val_by_id:
            self.val_by_id[result['id']] = 'default_%s' % field

    def process_create_network(self, plugin_context, data, result):
        session = plugin_context.session
        self._check_create(session, data, result)
        self._store_change(result, data, 'network_extension')
        result['network_extension'] = self.val_by_id[result['id']]

    def process_update_network(self, plugin_context, data, result):
        session = plugin_context.session
        self._check_update(session, data, result)
        self._store_change(result, data, 'network_extension')
        result['network_extension'] = self.val_by_id[result['id']]

    def extend_network_dict(self, session, net_db, result):
        self._check_extend(session, result, net_db, models_v2.Network)
        result['network_extension'] = self.val_by_id.get(result['id'])

    def process_create_subnet(self, plugin_context, data, result):
        session = plugin_context.session
        self._check_create(session, data, result)
        self._store_change(result, data, 'subnet_extension')
        result['subnet_extension'] = self.val_by_id[result['id']]

    def process_update_subnet(self, plugin_context, data, result):
        session = plugin_context.session
        self._check_update(session, data, result)
        self._store_change(result, data, 'subnet_extension')
        result['subnet_extension'] = self.val_by_id[result['id']]

    def extend_subnet_dict(self, session, subnet_db, result):
        self._check_extend(
            session, result, subnet_db,
            expected_db_entry_class=models_v2.Subnet,
            expected_obj_entry_class=subnet_obj.Subnet)
        result['subnet_extension'] = self.val_by_id.get(result['id'])

    def process_create_port(self, plugin_context, data, result):
        session = plugin_context.session
        self._check_create(session, data, result)
        self._store_change(result, data, 'port_extension')
        result['port_extension'] = self.val_by_id[result['id']]

    def process_update_port(self, plugin_context, data, result):
        session = plugin_context.session
        self._check_update(session, data, result)
        self._store_change(result, data, 'port_extension')
        result['port_extension'] = self.val_by_id[result['id']]

    def extend_port_dict(self, session, port_db, result):
        self._check_extend(session, result, port_db, models_v2.Port)
        result['port_extension'] = self.val_by_id.get(result['id'])


class TestNetworkExtension(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    value = sa.Column(sa.String(64))
    network = orm.relationship(
        models_v2.Network,
        backref=orm.backref('extension', cascade='delete', uselist=False,
                            lazy='joined'))


class TestSubnetExtension(model_base.BASEV2):
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id', ondelete="CASCADE"),
                          primary_key=True)
    value = sa.Column(sa.String(64))
    subnet = orm.relationship(
        models_v2.Subnet,
        backref=orm.backref('extension', cascade='delete', uselist=False,
                            lazy='joined'))


class TestPortExtension(model_base.BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    value = sa.Column(sa.String(64))
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref('extension', cascade='delete', uselist=False,
                            lazy='joined'))


class TestDBExtensionDriver(TestExtensionDriverBase):
    def _get_value(self, data, key):
        value = data[key]
        if not validators.is_attr_set(value):
            value = ''
        return value

    def process_create_network(self, plugin_context, data, result):
        session = plugin_context.session
        value = self._get_value(data, 'network_extension')
        record = TestNetworkExtension(network_id=result['id'], value=value)
        session.add(record)
        result['network_extension'] = value

    def process_update_network(self, plugin_context, data, result):
        session = plugin_context.session
        record = (session.query(TestNetworkExtension).
                  filter_by(network_id=result['id']).one())
        value = data.get('network_extension')
        if value and value != record.value:
            record.value = value
        result['network_extension'] = record.value

    def extend_network_dict(self, session, net_db, result):
        result['network_extension'] = net_db.extension.value

    def process_create_subnet(self, plugin_context, data, result):
        session = plugin_context.session
        value = self._get_value(data, 'subnet_extension')
        record = TestSubnetExtension(subnet_id=result['id'], value=value)
        session.add(record)
        result['subnet_extension'] = value

    def process_update_subnet(self, plugin_context, data, result):
        session = plugin_context.session
        record = (session.query(TestSubnetExtension).
                  filter_by(subnet_id=result['id']).one())
        value = data.get('subnet_extension')
        if value and value != record.value:
            record.value = value
        result['subnet_extension'] = record.value

    def extend_subnet_dict(self, session, subnet_db, result):
        value = subnet_db.extension.value if subnet_db.extension else ''
        result['subnet_extension'] = value

    def process_create_port(self, plugin_context, data, result):
        session = plugin_context.session
        value = self._get_value(data, 'port_extension')
        record = TestPortExtension(port_id=result['id'], value=value)
        session.add(record)
        result['port_extension'] = value

    def process_update_port(self, plugin_context, data, result):
        session = plugin_context.session
        record = (session.query(TestPortExtension).
                  filter_by(port_id=result['id']).one())
        value = data.get('port_extension')
        if value and value != record.value:
            record.value = value
        result['port_extension'] = record.value

    def extend_port_dict(self, session, port_db, result):
        value = port_db.extension.value if port_db.extension else ''
        result['port_extension'] = value
