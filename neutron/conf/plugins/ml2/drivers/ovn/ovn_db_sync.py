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

from importlib.metadata import entry_points

from oslo_config import cfg

from neutron._i18n import _


SYNC_ENTRYPOINTS = 'neutron.ovn.db_sync'
MIGRATION_ENTRYPOINTS = 'neutron.ovn.db_migration'

sync_entrypoints = {
    entrypoint.name: entrypoint
    for entrypoint in entry_points(group=SYNC_ENTRYPOINTS)
}
migration_entrypoints = {
    entrypoint.name: entrypoint
    for entrypoint in entry_points(group=MIGRATION_ENTRYPOINTS)
}

INSTALLED_SYNC_PLUGINS = list(sync_entrypoints)
INSTALLED_MIGRATION_PLUGINS = list(migration_entrypoints)


CORE_OPTS = [
    cfg.StrOpt('sync_plugin',
               choices=INSTALLED_SYNC_PLUGINS,
               help=(_("The subproject to execute the command against. "
                       "Can be one of: '%s'.")
                     % "', '".join(INSTALLED_SYNC_PLUGINS))),
    cfg.StrOpt('migration_plugin',
               choices=INSTALLED_MIGRATION_PLUGINS,
               help=(_("The neutron db migration plugin to execute. "
                       "Can be one of: '%s'.")
                     % "', '".join(INSTALLED_MIGRATION_PLUGINS))),
]


def register_ovn_db_sync_cli_opts(conf):
    conf.register_cli_opts(CORE_OPTS)
