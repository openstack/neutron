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

import copy
from logging import config as logging_config
import os

from alembic import command as alembic_command
from alembic import config as alembic_config
from alembic import environment
from alembic import migration as alembic_migration
from alembic import script as alembic_script
from alembic import util as alembic_util
from oslo_config import cfg
from oslo_utils import fileutils
from oslo_utils import importutils

from neutron._i18n import _
from neutron.common import config as common_config
from neutron.conf.db import migration_cli
from neutron.db import migration
from neutron.db.migration.connection import DBConnection


HEAD_FILENAME = 'HEAD'
HEADS_FILENAME = 'HEADS'
CONTRACT_HEAD_FILENAME = 'CONTRACT_HEAD'
EXPAND_HEAD_FILENAME = 'EXPAND_HEAD'

CURRENT_RELEASE = migration.RELEASE_2026_1
RELEASES = (
    migration.LIBERTY,
    migration.MITAKA,
    migration.NEWTON,
    migration.OCATA,
    migration.PIKE,
    migration.QUEENS,
    migration.ROCKY,
    migration.STEIN,
    migration.TRAIN,
    migration.USSURI,
    migration.VICTORIA,
    migration.WALLABY,
    migration.XENA,
    migration.YOGA,
    migration.ZED,
    migration.RELEASE_2023_1,
    migration.RELEASE_2023_2,
    migration.RELEASE_2024_1,
    migration.RELEASE_2024_2,
    migration.RELEASE_2025_1,
    migration.RELEASE_2025_2,
    migration.RELEASE_2026_1,
)

EXPAND_BRANCH = 'expand'
CONTRACT_BRANCH = 'contract'
MIGRATION_BRANCHES = (EXPAND_BRANCH, CONTRACT_BRANCH)

neutron_alembic_ini = os.path.join(os.path.dirname(__file__), 'alembic.ini')

CONF = cfg.ConfigOpts()
migration_cli.register_db_cli_opts(CONF)


log_error = alembic_util.err
log_warning = alembic_util.warn
log_info = alembic_util.msg


def do_alembic_command(config, cmd, revision=None, desc=None, **kwargs):
    args = []
    if revision:
        args.append(revision)

    project = config.get_main_option('neutron_project')
    if desc:
        log_info(_('Running %(cmd)s (%(desc)s) for %(project)s ...') %
                 {'cmd': cmd, 'desc': desc, 'project': project})
    else:
        log_info(_('Running %(cmd)s for %(project)s ...') %
                 {'cmd': cmd, 'project': project})
    try:
        getattr(alembic_command, cmd)(config, *args, **kwargs)
    except alembic_util.CommandError as e:
        log_error(str(e))
    log_info(_('OK'))


def _get_alembic_entrypoint(project):
    if project not in migration_cli.migration_entrypoints:
        log_error(_('Sub-project %s not installed.') % project)
    return migration_cli.migration_entrypoints[project]


def do_generic_show(config, cmd):
    kwargs = {'verbose': CONF.command.verbose}
    do_alembic_command(config, cmd, **kwargs)


def do_check_migration(config, cmd):
    do_alembic_command(config, 'branches')
    validate_revisions(config)
    validate_head_files(config)


def add_alembic_subparser(sub, cmd):
    return sub.add_parser(cmd, help=getattr(alembic_command, cmd).__doc__)


def add_branch_options(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--expand', action='store_true')
    group.add_argument('--contract', action='store_true')
    return group


def _find_milestone_revisions(config, milestone, branch=None):
    """Return the revision(s) for a given milestone."""
    script = alembic_script.ScriptDirectory.from_config(config)
    return [
        (m.revision, label)
        for m in _get_revisions(script)
        for label in (m.branch_labels or [None])
        if milestone in getattr(m.module, 'neutron_milestone', []) and
        (branch is None or branch in m.branch_labels)
    ]


def do_upgrade(config, cmd):
    branch = None

    if ((CONF.command.revision or CONF.command.delta) and
            (CONF.command.expand or CONF.command.contract)):
        raise SystemExit(_(
            'Phase upgrade options do not accept revision specification'))

    if CONF.command.expand:
        branch = EXPAND_BRANCH
        revision = _get_branch_head(EXPAND_BRANCH)

    elif CONF.command.contract:
        branch = CONTRACT_BRANCH
        revision = _get_branch_head(CONTRACT_BRANCH)

    elif not CONF.command.revision and not CONF.command.delta:
        raise SystemExit(_('You must provide a revision or relative delta'))

    else:
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

        # leave branchless 'head' revision request backward compatible by
        # applying all heads in all available branches.
        if revision == 'head':
            revision = 'heads'

    if revision in migration.NEUTRON_MILESTONES:
        expand_revisions = _find_milestone_revisions(config, revision,
                                                     EXPAND_BRANCH)
        contract_revisions = _find_milestone_revisions(config, revision,
                                                       CONTRACT_BRANCH)
        # Expand revisions must be run before contract revisions
        revisions = expand_revisions + contract_revisions
    else:
        revisions = [(revision, branch)]

    for revision, branch in revisions:
        if not CONF.command.sql:
            run_sanity_checks(config, revision)
        do_alembic_command(config, cmd, revision=revision,
                           desc=branch, sql=CONF.command.sql)


def no_downgrade(config, cmd):
    raise SystemExit(_("Downgrade no longer supported"))


def do_stamp(config, cmd):
    do_alembic_command(config, cmd,
                       revision=CONF.command.revision,
                       sql=CONF.command.sql)


def _get_branch_head(branch):
    '''Get the latest @head specification for a branch.'''
    return '%s@head' % branch


def _check_bootstrap_new_branch(branch, version_path, addn_kwargs):
    addn_kwargs['version_path'] = version_path
    addn_kwargs['head'] = _get_branch_head(branch)
    if not os.path.exists(version_path):
        # Bootstrap initial directory structure
        fileutils.ensure_tree(version_path, mode=0o755)


def do_revision(config, cmd):
    kwargs = {
        'message': CONF.command.message,
        'autogenerate': CONF.command.autogenerate,
        'sql': CONF.command.sql,
    }
    branches = []
    if CONF.command.expand:
        kwargs['head'] = 'expand@head'
        branches.append(EXPAND_BRANCH)
    elif CONF.command.contract:
        kwargs['head'] = 'contract@head'
        branches.append(CONTRACT_BRANCH)
    else:
        branches = MIGRATION_BRANCHES

    if not CONF.command.autogenerate:
        for branch in branches:
            args = copy.copy(kwargs)
            version_path = _get_version_branch_path(
                config, release=CURRENT_RELEASE, branch=branch)
            _check_bootstrap_new_branch(branch, version_path, args)
            do_alembic_command(config, cmd, **args)
    else:
        # autogeneration code will take care of enforcing proper directories
        do_alembic_command(config, cmd, **kwargs)

    update_head_files(config)


def _get_release_labels(labels):
    result = set()
    for label in labels:
        # release labels were introduced Liberty for a short time and dropped
        # in that same release cycle
        result.add(f'{migration.LIBERTY}_{label}')
    return result


def _compare_labels(revision, expected_labels):
    # validate that the script has expected labels only
    bad_labels = revision.branch_labels - expected_labels
    if bad_labels:
        # NOTE(ihrachyshka): this hack is temporary to accommodate those
        # projects that already initialized their branches with liberty_*
        # labels. Let's notify them about the deprecation for now and drop it
        # later.
        bad_labels_with_release = (revision.branch_labels -
                                   _get_release_labels(expected_labels))
        if not bad_labels_with_release:
            log_warning(
                _('Release aware branch labels (%s) are deprecated. '
                  'Please switch to expand@ and contract@ '
                  'labels.') % bad_labels)
            return

        script_name = os.path.basename(revision.path)
        log_error(
            _('Unexpected label for script %(script_name)s: %(labels)s') %
            {'script_name': script_name,
             'labels': bad_labels}
        )


def _validate_single_revision_labels(script_dir, revision, label=None):
    expected_labels = set()
    if label is not None:
        expected_labels.add(label)

    _compare_labels(revision, expected_labels)

    # if it's not the root element of the branch, expect the parent of the
    # script to have the same label
    if revision.down_revision is not None:
        down_revision = script_dir.get_revision(revision.down_revision)
        _compare_labels(down_revision, expected_labels)


def _validate_revision(script_dir, revision):
    for branch in MIGRATION_BRANCHES:
        if branch in revision.path:
            _validate_single_revision_labels(
                script_dir, revision, label=branch)
            return

    # validate script from branchless part of migration rules
    _validate_single_revision_labels(script_dir, revision)


def validate_revisions(config):
    script_dir = alembic_script.ScriptDirectory.from_config(config)
    revisions = _get_revisions(script_dir)

    for revision in revisions:
        _validate_revision(script_dir, revision)

    branchpoints = _get_branch_points(script_dir)
    if len(branchpoints) > 1:
        branchpoints = ', '.join(p.revision for p in branchpoints)
        log_error(
            _('Unexpected number of alembic branch points: %(branchpoints)s') %
            {'branchpoints': branchpoints}
        )


def _get_revisions(script):
    return list(script.walk_revisions(base='base', head='heads'))


def _get_branch_points(script):
    branchpoints = []
    for revision in _get_revisions(script):
        if revision.is_branch_point:
            branchpoints.append(revision)
    return branchpoints


def _get_heads_map(config):
    script = alembic_script.ScriptDirectory.from_config(config)
    heads = script.get_heads()
    head_map = {}
    for head in heads:
        if CONTRACT_BRANCH in script.get_revision(head).branch_labels:
            head_map[CONTRACT_BRANCH] = head
        else:
            head_map[EXPAND_BRANCH] = head
    return head_map


def _check_head(branch_name, head_file, head):
    try:
        with open(head_file) as file_:
            observed_head = file_.read().strip()
    except OSError:
        pass
    else:
        if observed_head != head:
            log_error(
                _('%(branch)s HEAD file does not match migration timeline '
                  'head, expected: %(head)s') % {'branch': branch_name.title(),
                                                 'head': head})


def validate_head_files(config):
    '''Check that HEAD files contain the latest head for the branch.'''
    contract_head = _get_contract_head_file_path(config)
    expand_head = _get_expand_head_file_path(config)
    if not os.path.exists(contract_head) or not os.path.exists(expand_head):
        log_warning(_("Repository does not contain HEAD files for "
                      "contract and expand branches."))
        return
    head_map = _get_heads_map(config)
    _check_head(CONTRACT_BRANCH, contract_head, head_map[CONTRACT_BRANCH])
    _check_head(EXPAND_BRANCH, expand_head, head_map[EXPAND_BRANCH])


def update_head_files(config):
    '''Update HEAD files with the latest branch heads.'''
    head_map = _get_heads_map(config)
    contract_head = _get_contract_head_file_path(config)
    expand_head = _get_expand_head_file_path(config)
    with open(contract_head, 'w+') as f:
        f.write(head_map[CONTRACT_BRANCH] + '\n')
    with open(expand_head, 'w+') as f:
        f.write(head_map[EXPAND_BRANCH] + '\n')

    old_head_file = _get_head_file_path(config)
    old_heads_file = _get_heads_file_path(config)
    for file_ in (old_head_file, old_heads_file):
        fileutils.delete_if_exists(file_)


def _get_current_database_heads(config):
    with DBConnection(config.neutron_config.database.connection) as conn:
        opts = {
            'version_table': get_alembic_version_table(config)
        }
        context = alembic_migration.MigrationContext.configure(
            conn, opts=opts)
        return context.get_current_heads()


def has_offline_migrations(config, cmd):
    heads_map = _get_heads_map(config)
    if heads_map[CONTRACT_BRANCH] not in _get_current_database_heads(config):
        # If there is at least one contract revision not applied to database,
        # it means we should shut down all neutron-server instances before
        # proceeding with upgrade.
        project = config.get_main_option('neutron_project')
        log_info(_('Need to apply migrations from %(project)s '
                   'contract branch. This will require all Neutron '
                   'server instances to be shutdown before '
                   'proceeding with the upgrade.') %
                 {"project": project})
        return True
    return False


def add_command_parsers(subparsers):
    for name in ['current', 'history', 'branches', 'heads']:
        parser = add_alembic_subparser(subparsers, name)
        parser.set_defaults(func=do_generic_show)
        parser.add_argument('--verbose',
                            action='store_true',
                            help='Display more verbose output for the '
                                 'specified command')

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
    add_branch_options(parser)

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
    parser.add_argument('--sql', action='store_true')
    group = add_branch_options(parser)
    group.add_argument('--autogenerate', action='store_true')
    parser.set_defaults(func=do_revision)

    parser = subparsers.add_parser(
        'has_offline_migrations',
        help='Determine whether there are pending migration scripts that '
             'require full shutdown for all services that directly access '
             'database.')
    parser.set_defaults(func=has_offline_migrations)


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
        log_error(_("Failed to locate source for %s.") % project)
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
    '''Get heads file path

    Return the path of the file that was once used to maintain the list of
    latest heads.
    '''
    return os.path.join(
        _get_root_versions_dir(config),
        HEADS_FILENAME)


def _get_contract_head_file_path(config):
    '''Return the path of the file that is used to maintain contract head'''
    return os.path.join(
        _get_root_versions_dir(config),
        CONTRACT_HEAD_FILENAME)


def _get_expand_head_file_path(config):
    '''Return the path of the file that is used to maintain expand head'''
    return os.path.join(
        _get_root_versions_dir(config),
        EXPAND_HEAD_FILENAME)


def _get_version_branch_path(config, release=None, branch=None):
    version_path = _get_root_versions_dir(config)
    if branch and release:
        return os.path.join(version_path, release, branch)
    return version_path


def _set_version_locations(config):
    '''Make alembic see all revisions in all migration branches.'''
    split_branches = False
    version_paths = [_get_version_branch_path(config)]
    for release in RELEASES:
        for branch in MIGRATION_BRANCHES:
            version_path = _get_version_branch_path(config, release, branch)
            if split_branches or os.path.exists(version_path):
                split_branches = True
                version_paths.append(version_path)

    config.set_main_option('version_locations', ' '.join(version_paths))


def _get_installed_entrypoint(subproject):
    '''Get the entrypoint for the subproject, which must be installed.'''
    if subproject not in migration_cli.migration_entrypoints:
        log_error(_('Package %s not installed') % subproject)
    return migration_cli.migration_entrypoints[subproject]


def _get_subproject_script_location(subproject):
    '''Get the script location for the installed subproject.'''
    entrypoint = _get_installed_entrypoint(subproject)
    return ':'.join([entrypoint.module, entrypoint.attr])


def _get_subproject_base(subproject):
    '''Get the import base name for the installed subproject.'''
    entrypoint = _get_installed_entrypoint(subproject)
    return entrypoint.module.split('.')[0]


def get_alembic_version_table(config):
    script_dir = alembic_script.ScriptDirectory.from_config(config)
    alembic_version_table = [None]

    def alembic_version_table_from_env(rev, context):
        alembic_version_table[0] = context.version_table
        return []

    with environment.EnvironmentContext(config, script_dir,
                                        fn=alembic_version_table_from_env):
        script_dir.run_env()

    return alembic_version_table[0]


def get_alembic_configs():
    '''Return a list of alembic configs, one per project.
    '''

    # Get the script locations for the specified or installed projects.
    # Which projects to get script locations for is determined by the CLI
    # options as follows:
    #     --subproject P    # only subproject P (where P can be neutron)
    #     (none specified)  # neutron and all installed subprojects
    script_locations = {}
    if CONF.subproject:
        script_location = _get_subproject_script_location(CONF.subproject)
        script_locations[CONF.subproject] = script_location
    else:
        for subproject in migration_cli.migration_entrypoints:
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


def get_engine_config():
    return [obj for obj in migration_cli.DB_OPTS if obj.name == 'engine']


def main():
    common_config.register_common_config_options()
    # Interpret the config file for Python logging.
    # This line sets up loggers basically.
    logging_config.fileConfig(neutron_alembic_ini)

    CONF(project='neutron')
    return_val = False
    for config in get_alembic_configs():
        # TODO(gongysh) enable logging
        return_val |= bool(CONF.command.func(config, CONF.command.name))

    if CONF.command.name == 'has_offline_migrations' and not return_val:
        log_info(_('No offline migrations pending.'))

    return return_val
