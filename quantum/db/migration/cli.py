# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

import os
import sys

from alembic import command as alembic_command
from alembic import config as alembic_config
from alembic import util as alembic_util

from quantum import manager
from quantum.openstack.common import cfg

_core_opts = [
    cfg.StrOpt('core_plugin',
               default='',
               help='Quantum plugin provider module'),
]

_quota_opts = [
    cfg.StrOpt('quota_driver',
               default='',
               help='Quantum quota driver class'),
]

_db_opts = [
    cfg.StrOpt('sql_connection',
               default='',
               help='URL to database'),
]

_cmd_opts = [
    cfg.StrOpt('message',
               short='m',
               default='',
               help="Message string to use with 'revision'"),
    cfg.BoolOpt('autogenerate',
                default=False,
                help=("Populate revision script with candidate "
                      "migration operations, based on comparison "
                      "of database to model.")),
    cfg.BoolOpt('sql',
                default=False,
                help=("Don't emit SQL to database - dump to "
                      "standard output/file instead")),
    cfg.IntOpt('delta',
               default=0,
               help='Number of relative migrations to upgrade/downgrade'),

]

CONF = cfg.CommonConfigOpts()
CONF.register_opts(_core_opts)
CONF.register_opts(_db_opts, 'DATABASE')
CONF.register_opts(_quota_opts, 'QUOTAS')
CONF.register_cli_opts(_cmd_opts)


def main():
    config = alembic_config.Config(
        os.path.join(os.path.dirname(__file__), 'alembic.ini')
    )
    config.set_main_option('script_location',
                           'quantum.db.migration:alembic_migrations')
    # attach the Quantum conf to the Alembic conf
    config.quantum_config = CONF

    cmd, args, kwargs = process_argv(sys.argv)

    try:
        getattr(alembic_command, cmd)(config, *args, **kwargs)
    except alembic_util.CommandError, e:
        alembic_util.err(str(e))


def process_argv(argv):
    positional = CONF(argv)

    if len(positional) > 1:
        cmd = positional[1]
        revision = positional[2:] and positional[2:][0]

        args = ()
        kwargs = {}

        if cmd == 'stamp':
            args = (revision,)
            kwargs = {'sql': CONF.sql}
        elif cmd in ('current', 'history'):
            pass  # these commands do not require additional args
        elif cmd in ('upgrade', 'downgrade'):
            if CONF.delta:
                revision = '%s%d' % ({'upgrade': '+', 'downgrade': '-'}[cmd],
                                     CONF.delta)
            elif not revision:
                raise SystemExit(
                    _('You must provide a revision or relative delta')
                )
            args = (revision,)
            kwargs = {'sql': CONF.sql}
        elif cmd == 'revision':
            kwargs = {
                'message': CONF.message,
                'autogenerate': CONF.autogenerate,
                'sql': CONF.sql}
        elif cmd == 'check_migration':
            cmd = 'branches'
        else:
            raise SystemExit(_('Unrecognized Command: %s') % cmd)

        return cmd, args, kwargs
    else:
        raise SystemExit(_('You must provide a sub-command'))
