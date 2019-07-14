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

from oslo_config import cfg
import pkg_resources

from neutron._i18n import _


MIGRATION_ENTRYPOINTS = 'neutron.db.alembic_migrations'
migration_entrypoints = {
    entrypoint.name: entrypoint
    for entrypoint in pkg_resources.iter_entry_points(MIGRATION_ENTRYPOINTS)
}

INSTALLED_SUBPROJECTS = [project_ for project_ in migration_entrypoints]

CORE_OPTS = [
    cfg.StrOpt('subproject',
               choices=INSTALLED_SUBPROJECTS,
               help=(_("The subproject to execute the command against. "
                       "Can be one of: '%s'.")
                     % "', '".join(INSTALLED_SUBPROJECTS)))
]

DB_OPTS = [
    cfg.StrOpt('connection',
               default='',
               secret=True,
               help=_('URL to database')),
    cfg.StrOpt('engine',
               default='',
               help=_('Database engine for which script will be generated '
                      'when using offline migration.')),
]


def register_db_cli_opts(conf):
    conf.register_cli_opts(CORE_OPTS)
    conf.register_cli_opts(DB_OPTS, 'database')
