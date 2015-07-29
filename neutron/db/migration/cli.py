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
import pkg_resources

from neutron.common import utils


# TODO(ihrachyshka): maintain separate HEAD files per branch
HEAD_FILENAME = 'HEAD'
HEADS_FILENAME = 'HEADS'
CURRENT_RELEASE = "liberty"
MIGRATION_BRANCHES = ('expand', 'contract')

MIGRATION_ENTRYPOINTS = 'neutron.db.alembic_migrations'
migration_entrypoints = {
    entrypoint.name: entrypoint
    for entrypoint in pkg_resources.iter_entry_points(MIGRATION_ENTRYPOINTS)
}

neutron_alembic_ini = os.path.join(os.path.dirname(__file__), 'alembic.ini')

VALID_SERVICES = ['fwaas', 'lbaas', 'vpnaas']
INSTALLED_SERVICES = [service_ for service_ in VALID_SERVICES
                      if 'neutron-%s' % service_ in migration_entrypoints]
INSTALLED_SERVICE_PROJECTS = ['neutron-%s' % service_
                              for service_ in INSTALLED_SERVICES]
INSTALLED_SUBPROJECTS = [project_ for project_ in migration_entrypoints
                         if project_ not in INSTALLED_SERVICE_PROJECTS]

service_help = (
    _("Can be one of '%s'.") % "', '".join(INSTALLED_SERVICES)
    if INSTALLED_SERVICES else
    _("(No services are currently installed).")
)

_core_opts = [
    cfg.StrOpt('core_plugin',
               default='',
               help=_('Neutron plugin provider module')),
    cfg.StrOpt('service',
               choices=INSTALLED_SERVICES,
               help=(_("The advanced service to execute the command against. ")
                     + service_help)),
    cfg.StrOpt('subproject',
               choices=INSTALLED_SUBPROJECTS,
               help=(_("The subproject to execute the command against. "
                       "Can be one of %s.") % INSTALLED_SUBPROJECTS)),
    cfg.BoolOpt('split_branches',
                default=False,
                help=_("Enforce using split branches file structure."))
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
    project = config.get_main_option('neutron_project')
    alembic_util.msg(_('Running %(cmd)s for %(project)s ...') %
                     {'cmd': cmd, 'project': project})
    try:
        getattr(alembic_command, cmd)(config, *args, **kwargs)
    except alembic_util.CommandError as e:
        alembic_util.err(six.text_type(e))
    alembic_util.msg(_('OK'))


def _get_alembic_entrypoint(project):
    if project not in migration_entrypoints:
        alembic_util.err(_('Sub-project %s not installed.') % project)
    return migration_entrypoints[project]


def do_check_migration(config, cmd):
    do_alembic_command(config, 'branches')
    validate_heads_file(config)


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

    # leave branchless 'head' revision request backward compatible by applying
    # all heads in all available branches.
    if revision == 'head':
        revision = 'heads'
    if not CONF.command.sql:
        run_sanity_checks(config, revision)
    do_alembic_command(config, cmd, revision, sql=CONF.command.sql)


def no_downgrade(config, cmd):
    raise SystemExit(_("Downgrade no longer supported"))


def do_stamp(config, cmd):
    do_alembic_command(config, cmd,
                       CONF.command.revision,
                       sql=CONF.command.sql)


def _get_branch_label(branch):
    '''Get the latest branch label corresponding to release cycle.'''
    return '%s_%s' % (CURRENT_RELEASE, branch)


def _get_branch_head(branch):
    '''Get the latest @head specification for a branch.'''
    return '%s@head' % _get_branch_label(branch)


def do_revision(config, cmd):
    '''Generate new revision files, one per branch.'''
    addn_kwargs = {
        'message': CONF.command.message,
        'autogenerate': CONF.command.autogenerate,
        'sql': CONF.command.sql,
    }

    if _use_separate_migration_branches(config):
        for branch in MIGRATION_BRANCHES:
            version_path = _get_version_branch_path(config, branch)
            addn_kwargs['version_path'] = version_path

            if not os.path.exists(version_path):
                # Bootstrap initial directory structure
                utils.ensure_dir(version_path)
                # Each new release stream of migrations is detached from
                # previous migration chains
                addn_kwargs['head'] = 'base'
                # Mark the very first revision in the new branch with its label
                addn_kwargs['branch_label'] = _get_branch_label(branch)
                # TODO(ihrachyshka): ideally, we would also add depends_on here
                # to refer to the head of the previous release stream. But
                # alembic API does not support it yet.
            else:
                addn_kwargs['head'] = _get_branch_head(branch)

            do_alembic_command(config, cmd, **addn_kwargs)
    else:
        do_alembic_command(config, cmd, **addn_kwargs)
    update_heads_file(config)


def _get_sorted_heads(script):
    '''Get the list of heads for all branches, sorted.'''
    heads = script.get_heads()
    # +1 stands for the core 'kilo' branch, the one that didn't have branches
    if len(heads) > len(MIGRATION_BRANCHES) + 1:
        alembic_util.err(_('No new branches are allowed except: %s') %
                         ' '.join(MIGRATION_BRANCHES))
    return sorted(heads)


def validate_heads_file(config):
    '''Check that HEADS file contains the latest heads for each branch.'''
    script = alembic_script.ScriptDirectory.from_config(config)
    expected_heads = _get_sorted_heads(script)
    heads_path = _get_active_head_file_path(config)
    try:
        with open(heads_path) as file_:
            observed_heads = file_.read().split()
            if observed_heads == expected_heads:
                return
    except IOError:
        pass
    alembic_util.err(
        _('HEADS file does not match migration timeline heads, expected: %s')
        % ', '.join(expected_heads))


def update_heads_file(config):
    '''Update HEADS file with the latest branch heads.'''
    script = alembic_script.ScriptDirectory.from_config(config)
    heads = _get_sorted_heads(script)
    heads_path = _get_active_head_file_path(config)
    with open(heads_path, 'w+') as f:
        f.write('\n'.join(heads))
    if _use_separate_migration_branches(config):
        old_head_file = _get_head_file_path(config)
        if os.path.exists(old_head_file):
            os.remove(old_head_file)


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


def _get_project_base(config):
    '''Return the base python namespace name for a project.'''
    script_location = config.get_main_option('script_location')
    return script_location.split(':')[0].split('.')[0]


def _get_package_root_dir(config):
    root_module = importutils.try_import(_get_project_base(config))
    if not root_module:
        project = config.get_main_option('neutron_project')
        alembic_util.err(_("Failed to locate source for %s.") % project)
    # The root_module.__file__ property is a path like
    #    '/opt/stack/networking-foo/networking_foo/__init__.py'
    # We return just
    #    '/opt/stack/networking-foo'
    return os.path.dirname(os.path.dirname(root_module.__file__))


def _get_root_versions_dir(config):
    '''Return root directory that contains all migration rules.'''
    root_dir = _get_package_root_dir(config)
    script_location = config.get_main_option('script_location')
    # Script location is something like:
    #   'project_base.db.migration:alembic_migrations'
    # Convert it to:
    #   'project_base/db/migration/alembic_migrations/versions'
    part1, part2 = script_location.split(':')
    parts = part1.split('.') + part2.split('.') + ['versions']
    # Return the absolute path to the versions dir
    return os.path.join(root_dir, *parts)


def _get_head_file_path(config):
    '''Return the path of the file that contains single head.'''
    return os.path.join(
        _get_root_versions_dir(config),
        HEAD_FILENAME)


def _get_heads_file_path(config):
    '''Return the path of the file that contains all latest heads, sorted.'''
    return os.path.join(
        _get_root_versions_dir(config),
        HEADS_FILENAME)


def _get_active_head_file_path(config):
    '''Return the path of the file that contains latest head(s), depending on
       whether multiple branches are used.
    '''
    if _use_separate_migration_branches(config):
        return _get_heads_file_path(config)
    return _get_head_file_path(config)


def _get_version_branch_path(config, branch=None):
    version_path = _get_root_versions_dir(config)
    if branch:
        return os.path.join(version_path, CURRENT_RELEASE, branch)
    return version_path


def _use_separate_migration_branches(config):
    '''Detect whether split migration branches should be used.'''
    return (CONF.split_branches or
            # Use HEADS file to indicate the new, split migration world
            os.path.exists(_get_heads_file_path(config)))


def _set_version_locations(config):
    '''Make alembic see all revisions in all migration branches.'''
    version_paths = [_get_version_branch_path(config)]
    if _use_separate_migration_branches(config):
        for branch in MIGRATION_BRANCHES:
            version_paths.append(_get_version_branch_path(config, branch))

    config.set_main_option('version_locations', ' '.join(version_paths))


def _get_installed_entrypoint(subproject):
    '''Get the entrypoint for the subproject, which must be installed.'''
    if subproject not in migration_entrypoints:
        alembic_util.err(_('Package %s not installed') % subproject)
    return migration_entrypoints[subproject]


def _get_subproject_script_location(subproject):
    '''Get the script location for the installed subproject.'''
    entrypoint = _get_installed_entrypoint(subproject)
    return ':'.join([entrypoint.module_name, entrypoint.attrs[0]])


def _get_service_script_location(service):
    '''Get the script location for the service, which must be installed.'''
    return _get_subproject_script_location('neutron-%s' % service)


def _get_subproject_base(subproject):
    '''Get the import base name for the installed subproject.'''
    entrypoint = _get_installed_entrypoint(subproject)
    return entrypoint.module_name.split('.')[0]


def get_alembic_configs():
    '''Return a list of alembic configs, one per project.
    '''

    # Get the script locations for the specified or installed projects.
    # Which projects to get script locations for is determined by the CLI
    # options as follows:
    #     --service X       # only subproject neutron-X
    #     --subproject Y    # only subproject Y
    #     (none specified)  # neutron and all installed subprojects
    script_locations = {}
    if CONF.service:
        script_location = _get_service_script_location(CONF.service)
        script_locations['neutron-%s' % CONF.service] = script_location
    elif CONF.subproject:
        script_location = _get_subproject_script_location(CONF.subproject)
        script_locations[CONF.subproject] = script_location
    else:
        for subproject, ep in migration_entrypoints.items():
            script_locations[subproject] = _get_subproject_script_location(
                subproject)

    # Return a list of alembic configs from the projects in the
    # script_locations dict. If neutron is in the list it is first.
    configs = []
    project_seq = sorted(script_locations.keys())
    # Core neutron must be the first project if there is more than one
    if len(project_seq) > 1 and 'neutron' in project_seq:
        project_seq.insert(0, project_seq.pop(project_seq.index('neutron')))
    for project in project_seq:
        config = alembic_config.Config(neutron_alembic_ini)
        config.set_main_option('neutron_project', project)
        script_location = script_locations[project]
        config.set_main_option('script_location', script_location)
        _set_version_locations(config)
        config.neutron_config = CONF
        configs.append(config)

    return configs


def get_neutron_config():
    # Neutron's alembic config is always the first one
    return get_alembic_configs()[0]


def run_sanity_checks(config, revision):
    script_dir = alembic_script.ScriptDirectory.from_config(config)

    def check_sanity(rev, context):
        # TODO(ihrachyshka): here we use internal API for alembic; we may need
        # alembic to expose implicit_base= argument into public
        # iterate_revisions() call
        for script in script_dir.revision_map.iterate_revisions(
                revision, rev, implicit_base=True):
            if hasattr(script.module, 'check_sanity'):
                script.module.check_sanity(context.connection)
        return []

    with environment.EnvironmentContext(config, script_dir,
                                        fn=check_sanity,
                                        starting_rev=None,
                                        destination_rev=revision):
        script_dir.run_env()


def validate_cli_options():
    if CONF.subproject and CONF.service:
        alembic_util.err(_("Cannot specify both --service and --subproject."))


def main():
    CONF(project='neutron')
    validate_cli_options()
    for config in get_alembic_configs():
        #TODO(gongysh) enable logging
        CONF.command.func(config, CONF.command.name)
