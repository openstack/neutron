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

from alembic import command as alembic_command
from alembic import config as alembic_config
from alembic import environment
from alembic import script as alembic_script
from alembic import util as alembic_util
import debtcollector
from oslo_config import cfg
from oslo_utils import fileutils
from oslo_utils import importutils
import pkg_resources
import six

from neutron.common import utils
from neutron.db import migration


HEAD_FILENAME = 'HEAD'
HEADS_FILENAME = 'HEADS'
CONTRACT_HEAD_FILENAME = 'CONTRACT_HEAD'
EXPAND_HEAD_FILENAME = 'EXPAND_HEAD'

CURRENT_RELEASE = migration.MITAKA
RELEASES = (
    migration.LIBERTY,
    migration.MITAKA,
)

EXPAND_BRANCH = 'expand'
CONTRACT_BRANCH = 'contract'
MIGRATION_BRANCHES = (EXPAND_BRANCH, CONTRACT_BRANCH)

MIGRATION_ENTRYPOINTS = 'neutron.db.alembic_migrations'
migration_entrypoints = {
    entrypoint.name: entrypoint
    for entrypoint in pkg_resources.iter_entry_points(MIGRATION_ENTRYPOINTS)
}


BRANCHLESS_WARNING = 'Branchless migration chains are deprecated as of Mitaka.'


neutron_alembic_ini = os.path.join(os.path.dirname(__file__), 'alembic.ini')

VALID_SERVICES = ['fwaas', 'lbaas', 'vpnaas']
INSTALLED_SERVICES = [service_ for service_ in VALID_SERVICES
                      if 'neutron-%s' % service_ in migration_entrypoints]
INSTALLED_SUBPROJECTS = [project_ for project_ in migration_entrypoints]

_core_opts = [
    cfg.StrOpt('core_plugin',
               default='',
               help=_('Neutron plugin provider module'),
               deprecated_for_removal=True),
    cfg.StrOpt('service',
               choices=INSTALLED_SERVICES,
               help=(_("(Deprecated. Use '--subproject neutron-SERVICE' "
                       "instead.) The advanced service to execute the "
                       "command against.")),
               deprecated_for_removal=True),
    cfg.StrOpt('subproject',
               choices=INSTALLED_SUBPROJECTS,
               help=(_("The subproject to execute the command against. "
                       "Can be one of: '%s'.")
                     % "', '".join(INSTALLED_SUBPROJECTS))),
    cfg.BoolOpt('split_branches',
                default=False,
                help=_("Enforce using split branches file structure."))
]

_quota_opts = [
    cfg.StrOpt('quota_driver',
               default='',
               help=_('Neutron quota driver class'),
               deprecated_for_removal=True),
]

_db_opts = [
    cfg.StrOpt('connection',
               deprecated_name='sql_connection',
               default='',
               secret=True,
               help=_('URL to database')),
    cfg.StrOpt('engine',
               default='',
               help=_('Database engine for which script will be generated '
                      'when using offline migration.')),
]

CONF = cfg.ConfigOpts()
CONF.register_cli_opts(_core_opts)
CONF.register_cli_opts(_db_opts, 'database')
CONF.register_opts(_quota_opts, 'QUOTAS')


def do_alembic_command(config, cmd, revision=None, desc=None, **kwargs):
    args = []
    if revision:
        args.append(revision)

    project = config.get_main_option('neutron_project')
    if desc:
        alembic_util.msg(_('Running %(cmd)s (%(desc)s) for %(project)s ...') %
                         {'cmd': cmd, 'desc': desc, 'project': project})
    else:
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


def do_generic_show(config, cmd):
    kwargs = {'verbose': CONF.command.verbose}
    do_alembic_command(config, cmd, **kwargs)


def do_check_migration(config, cmd):
    do_alembic_command(config, 'branches')
    validate_revisions(config)
    validate_head_file(config)


def add_alembic_subparser(sub, cmd):
    return sub.add_parser(cmd, help=getattr(alembic_command, cmd).__doc__)


def add_branch_options(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--expand', action='store_true')
    group.add_argument('--contract', action='store_true')


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
        revisions = _find_milestone_revisions(config, revision, branch)
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
        utils.ensure_dir(version_path)


def do_revision(config, cmd):
    kwargs = {
        'message': CONF.command.message,
        'autogenerate': CONF.command.autogenerate,
        'sql': CONF.command.sql,
    }
    if CONF.command.expand:
        kwargs['head'] = 'expand@head'
    elif CONF.command.contract:
        kwargs['head'] = 'contract@head'

    do_alembic_command(config, cmd, **kwargs)
    if _use_separate_migration_branches(config):
        update_head_files(config)
    else:
        update_head_file(config)


def _get_release_labels(labels):
    result = set()
    for label in labels:
        # release labels were introduced Liberty for a short time and dropped
        # in that same release cycle
        result.add('%s_%s' % (migration.LIBERTY, label))
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
            alembic_util.warn(
                _('Release aware branch labels (%s) are deprecated. '
                  'Please switch to expand@ and contract@ '
                  'labels.') % bad_labels)
            return

        script_name = os.path.basename(revision.path)
        alembic_util.err(
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
        alembic_util.err(
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


def validate_head_file(config):
    '''Check that HEAD file contains the latest head for the branch.'''
    if _use_separate_migration_branches(config):
        _validate_head_files(config)
    else:
        _validate_head_file(config)


@debtcollector.removals.remove(message=BRANCHLESS_WARNING)
def _validate_head_file(config):
    '''Check that HEAD file contains the latest head for the branch.'''
    script = alembic_script.ScriptDirectory.from_config(config)
    expected_head = script.get_heads()
    head_path = _get_head_file_path(config)
    try:
        with open(head_path) as file_:
            observed_head = file_.read().split()
            if observed_head == expected_head:
                return
    except IOError:
        pass
    alembic_util.err(
        _('HEAD file does not match migration timeline head, expected: %s')
        % expected_head)


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
    except IOError:
        pass
    else:
        if observed_head != head:
            alembic_util.err(
                _('%(branch)s HEAD file does not match migration timeline '
                  'head, expected: %(head)s') % {'branch': branch_name.title(),
                                                 'head': head})


def _validate_head_files(config):
    '''Check that HEAD files contain the latest head for the branch.'''
    contract_head = _get_contract_head_file_path(config)
    expand_head = _get_expand_head_file_path(config)
    if not os.path.exists(contract_head) or not os.path.exists(expand_head):
        alembic_util.warn(_("Repository does not contain HEAD files for "
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


@debtcollector.removals.remove(message=BRANCHLESS_WARNING)
def update_head_file(config):
    script = alembic_script.ScriptDirectory.from_config(config)
    head = script.get_heads()
    with open(_get_head_file_path(config), 'w+') as f:
        f.write('\n'.join(head))


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
    parser.add_argument('--autogenerate', action='store_true')
    parser.add_argument('--sql', action='store_true')
    add_branch_options(parser)
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
    '''
    Return the path of the file that was once used to maintain the list of
    latest heads.
    '''
    return os.path.join(
        _get_root_versions_dir(config),
        HEADS_FILENAME)


def _get_contract_head_file_path(config):
    '''
    Return the path of the file that is used to maintain contract head
    '''
    return os.path.join(
        _get_root_versions_dir(config),
        CONTRACT_HEAD_FILENAME)


def _get_expand_head_file_path(config):
    '''
    Return the path of the file that is used to maintain expand head
    '''
    return os.path.join(
        _get_root_versions_dir(config),
        EXPAND_HEAD_FILENAME)


def _get_version_branch_path(config, release=None, branch=None):
    version_path = _get_root_versions_dir(config)
    if branch and release:
        return os.path.join(version_path, release, branch)
    return version_path


def _use_separate_migration_branches(config):
    '''Detect whether split migration branches should be used.'''
    if CONF.split_branches:
        return True

    script_dir = alembic_script.ScriptDirectory.from_config(config)
    if _get_branch_points(script_dir):
        return True

    return False


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
    #     --service X       # only subproject neutron-X (deprecated)
    #     --subproject Y    # only subproject Y (where Y can be neutron)
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


def get_engine_config():
    return [obj for obj in _db_opts if obj.name == 'engine']


def main():
    CONF(project='neutron')
    validate_cli_options()
    for config in get_alembic_configs():
        #TODO(gongysh) enable logging
        CONF.command.func(config, CONF.command.name)
