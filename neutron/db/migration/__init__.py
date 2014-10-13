# Copyright 2012 New Dream Network, LLC (DreamHost)
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
# @author: Mark McClain, DreamHost

from alembic import context
from alembic import op
import sqlalchemy as sa

OVS_PLUGIN = ('neutron.plugins.openvswitch.ovs_neutron_plugin'
              '.OVSNeutronPluginV2')
CISCO_PLUGIN = 'neutron.plugins.cisco.network_plugin.PluginV2'


def should_run(active_plugins, migrate_plugins):
    if '*' in migrate_plugins:
        return True
    else:
        if (CISCO_PLUGIN not in migrate_plugins and
                OVS_PLUGIN in migrate_plugins):
            migrate_plugins.append(CISCO_PLUGIN)
        return set(active_plugins) & set(migrate_plugins)


def create_table_if_not_exist(table_name, *args, **kwargs):
    if not context.is_offline_mode():
        bind = op.get_bind()
        insp = sa.engine.reflection.Inspector.from_engine(bind)
        if table_name in insp.get_table_names():
            return

    op.create_table(table_name, *args, **kwargs)
