# Copyright (c) 2015 Red Hat
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

from alembic.operations import ops
from alembic.util import Dispatcher
from alembic.util import rev_id as new_rev_id

from neutron._i18n import _
from neutron.db.migration import cli

_ec_dispatcher = Dispatcher()


def process_revision_directives(context, revision, directives):
    directives[:] = list(_assign_directives(context, directives))


def _assign_directives(context, directives, phase=None):
    for directive in directives:
        decider = _ec_dispatcher.dispatch(directive)
        if phase is None:
            phases = cli.MIGRATION_BRANCHES
        else:
            phases = (phase,)
        for phase in phases:
            decided = decider(context, directive, phase)
            if decided:
                yield decided


@_ec_dispatcher.dispatch_for(ops.MigrationScript)
def _migration_script_ops(context, directive, phase):
    """Generate a new ops.MigrationScript() for a given phase.

    E.g. given an ops.MigrationScript() directive from a vanilla autogenerate
    and an expand/contract phase name, produce a new ops.MigrationScript()
    which contains only those sub-directives appropriate to "expand" or
    "contract".  Also ensure that the branch directory exists and that
    the correct branch labels/depends_on/head revision are set up.

    """
    version_path = cli._get_version_branch_path(
        context.config, release=cli.CURRENT_RELEASE, branch=phase)
    autogen_kwargs = {}
    cli._check_bootstrap_new_branch(phase, version_path, autogen_kwargs)

    op = ops.MigrationScript(
        new_rev_id(),
        ops.UpgradeOps(ops=list(
            _assign_directives(context, directive.upgrade_ops.ops, phase)
        )),
        ops.DowngradeOps(ops=[]),
        message=directive.message,
        **autogen_kwargs
    )

    if not op.upgrade_ops.is_empty():
        return op


@_ec_dispatcher.dispatch_for(ops.AddConstraintOp)
@_ec_dispatcher.dispatch_for(ops.CreateIndexOp)
@_ec_dispatcher.dispatch_for(ops.CreateTableOp)
@_ec_dispatcher.dispatch_for(ops.AddColumnOp)
def _expands(context, directive, phase):
    if phase == 'expand':
        return directive
    else:
        return None


@_ec_dispatcher.dispatch_for(ops.DropConstraintOp)
@_ec_dispatcher.dispatch_for(ops.DropIndexOp)
@_ec_dispatcher.dispatch_for(ops.DropTableOp)
@_ec_dispatcher.dispatch_for(ops.DropColumnOp)
def _contracts(context, directive, phase):
    if phase == 'contract':
        return directive
    else:
        return None


@_ec_dispatcher.dispatch_for(ops.AlterColumnOp)
def _alter_column(context, directive, phase):
    is_expand = phase == 'expand'

    if is_expand and directive.modify_nullable is True:
        return directive
    elif not is_expand and directive.modify_nullable is False:
        return directive
    else:
        raise NotImplementedError(
            _("Don't know if operation is an expand or "
              "contract at the moment: %s") % directive)


@_ec_dispatcher.dispatch_for(ops.ModifyTableOps)
def _modify_table_ops(context, directive, phase):
    op = ops.ModifyTableOps(
        directive.table_name,
        ops=list(_assign_directives(context, directive.ops, phase)),
        schema=directive.schema)
    if not op.is_empty():
        return op
