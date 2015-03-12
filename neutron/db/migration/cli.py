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

import os
import six

from alembic import command as alembic_command
from alembic import config as alembic_config
from alembic import environment
from alembic import script as alembic_script
from alembic import util as alembic_util
from oslo_config import cfg
from oslo_utils import importutils

from neutron.common import repos

HEAD_FILENAME = 'HEAD'

mods = repos.NeutronModules()
VALID_SERVICES = map(mods.alembic_name, mods.installed_list())


_core_opts = [
    cfg.StrOpt('core_plugin',
               default='',
               help=_('Neutron plugin provider module')),
    cfg.ListOpt('service_plugins',
                default=[],
                help=_("The service plugins Neutron will use")),
    cfg.StrOpt('service',
               choices=VALID_SERVICES,
               help=_("The advanced service to execute the command against. "
                      "Can be one of '%s'.") % "', '".join(VALID_SERVICES))
]

_quota_opts = [
    cfg.StrOpt('quota_driver',
               default='',
               help=_('Neutron quota driver class')),
]

_db_opts = [
    cfg.StrOpt('connection',
               deprecated_name='sql_connection',
               default='',
               secret=True,
               help=_('URL to database')),
    cfg.StrOpt('engine',
               default='',
               help=_('Database engine')),
]

CONF = cfg.ConfigOpts()
CONF.register_cli_opts(_core_opts)
CONF.register_cli_opts(_db_opts, 'database')
CONF.register_opts(_quota_opts, 'QUOTAS')


def do_alembic_command(config, cmd, *args, **kwargs):
    try:
        getattr(alembic_command, cmd)(config, *args, **kwargs)
    except alembic_util.CommandError as e:
        alembic_util.err(six.text_type(e))


def do_check_migration(config, cmd):
    do_alembic_command(config, 'branches')
    validate_head_file(config)


def add_alembic_subparser(sub, cmd):
    return sub.add_parser(cmd, help=getattr(alembic_command, cmd).__doc__)


def do_upgrade(config, cmd):
    if not CONF.command.revision and not CONF.command.delta:
        raise SystemExit(_('You must provide a revision or relative delta'))

    revision = CONF.command.revision or ''
    if '-' in revision:
        raise SystemExit(_('Negative relative revision (downgrade) not '
                           'supported'))

    delta = CONF.command.delta
    if delta:
        if '+' in revision:
            raise SystemExit(_('Use either --delta or relative revision, '
                               'not both'))
        if delta < 0:
            raise SystemExit(_('Negative delta (downgrade) not supported'))
        revision = '%s+%d' % (revision, delta)

    if not CONF.command.sql:
        run_sanity_checks(config, revision)
    do_alembic_command(config, cmd, revision, sql=CONF.command.sql)


def no_downgrade(config, cmd):
    raise SystemExit(_("Downgrade no longer supported"))


def do_stamp(config, cmd):
    do_alembic_command(config, cmd,
                       CONF.command.revision,
                       sql=CONF.command.sql)


def do_revision(config, cmd):
    do_alembic_command(config, cmd,
                       message=CONF.command.message,
                       autogenerate=CONF.command.autogenerate,
                       sql=CONF.command.sql)
    update_head_file(config)


def validate_head_file(config):
    script = alembic_script.ScriptDirectory.from_config(config)
    if len(script.get_heads()) > 1:
        alembic_util.err(_('Timeline branches unable to generate timeline'))

    head_path = os.path.join(script.versions, HEAD_FILENAME)
    if (os.path.isfile(head_path) and
        open(head_path).read().strip() == script.get_current_head()):
        return
    else:
        alembic_util.err(_('HEAD file does not match migration timeline head'))


def update_head_file(config):
    script = alembic_script.ScriptDirectory.from_config(config)
    if len(script.get_heads()) > 1:
        alembic_util.err(_('Timeline branches unable to generate timeline'))

    head_path = os.path.join(script.versions, HEAD_FILENAME)
    with open(head_path, 'w+') as f:
        f.write(script.get_current_head())


def add_command_parsers(subparsers):
    for name in ['current', 'history', 'branches']:
        parser = add_alembic_subparser(subparsers, name)
        parser.set_defaults(func=do_alembic_command)

    help_text = (getattr(alembic_command, 'branches').__doc__ +
                 ' and validate head file')
    parser = subparsers.add_parser('check_migration', help=help_text)
    parser.set_defaults(func=do_check_migration)

    parser = add_alembic_subparser(subparsers, 'upgrade')
    parser.add_argument('--delta', type=int)
    parser.add_argument('--sql', action='store_true')
    parser.add_argument('revision', nargs='?')
    parser.add_argument('--mysql-engine',
                        default='',
                        help='Change MySQL storage engine of current '
                             'existing tables')
    parser.set_defaults(func=do_upgrade)

    parser = subparsers.add_parser('downgrade', help="(No longer supported)")
    parser.add_argument('None', nargs='?', help="Downgrade not supported")
    parser.set_defaults(func=no_downgrade)

    parser = add_alembic_subparser(subparsers, 'stamp')
    parser.add_argument('--sql', action='store_true')
    parser.add_argument('revision')
    parser.set_defaults(func=do_stamp)

    parser = add_alembic_subparser(subparsers, 'revision')
    parser.add_argument('-m', '--message')
    parser.add_argument('--autogenerate', action='store_true')
    parser.add_argument('--sql', action='store_true')
    parser.set_defaults(func=do_revision)


command_opt = cfg.SubCommandOpt('command',
                                title='Command',
                                help=_('Available commands'),
                                handler=add_command_parsers)

CONF.register_cli_opt(command_opt)


def validate_service_installed(service):
    if not importutils.try_import('neutron_%s' % service):
        alembic_util.err(_('Package neutron-%s not installed') % service)


def get_script_location(neutron_config):
    location = '%s.db.migration:alembic_migrations'
    if neutron_config.service:
        validate_service_installed(neutron_config.service)
        base = "neutron_%s" % neutron_config.service
    else:
        base = "neutron"
    return location % base


def get_alembic_config():
    config = alembic_config.Config(os.path.join(os.path.dirname(__file__),
                                                'alembic.ini'))
    config.set_main_option('script_location', get_script_location(CONF))
    return config


def run_sanity_checks(config, revision):
    script_dir = alembic_script.ScriptDirectory.from_config(config)

    def check_sanity(rev, context):
        for script in script_dir.iterate_revisions(revision, rev):
            if hasattr(script.module, 'check_sanity'):
                script.module.check_sanity(context.connection)
        return []

    with environment.EnvironmentContext(config, script_dir,
                                        fn=check_sanity,
                                        starting_rev=None,
                                        destination_rev=revision):
        script_dir.run_env()


def main():
    CONF(project='neutron')
    config = get_alembic_config()
    config.neutron_config = CONF

    #TODO(gongysh) enable logging
    CONF.command.func(config, CONF.command.name)
