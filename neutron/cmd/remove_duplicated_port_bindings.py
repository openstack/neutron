# Copyright (c) 2022 Red Hat, Inc.
# All Rights Reserved.
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

from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_config import cfg
from oslo_db import options as db_options
from oslo_log import log as logging

from neutron.common import config as common_config  # noqa
from neutron.objects import ports as ports_obj


LOG = logging.getLogger(__name__)


def setup_conf(conf):
    db_group, neutron_db_opts = db_options.list_opts()[0]
    conf.register_cli_opts(neutron_db_opts, db_group)
    conf()


def main():
    """Main method for removing duplicated port binding and pb level registers.

    This script finds all ``PortBinding`` registers with the same ``port_id``.
    That happens during the live-migration process. Once finished, the inactive
    port binding register is deleted. However, it could happen that during the
    live-migration, an error occurs and this deletion is not executed. The
    related port cannot be migrated anymore.

    This script removes the inactive ``PortBinding`` referred to a port ID and
    the corresponding ``PortBindingLevel`` registers associated to this port
    ID and ``PortBinding.host``.

    This script should not be executed during a live migration process. It will
    remove the inactive port binding and will break the migration.
    """
    conf = cfg.CONF
    setup_conf(conf)
    _dry_run = conf.cli_script.dry_run
    admin_ctx = context.get_admin_context()
    with db_api.CONTEXT_WRITER.using(admin_ctx):
        dup_pbindings = ports_obj.PortBinding.get_duplicated_port_bindings(
            admin_ctx)

        # Clean duplicated port bindings that are INACTIVE and the
        # corresponding port binding level registers (if not in dry-run).
        if not _dry_run:
            for pbinding in dup_pbindings:
                port_id, host = pbinding.port_id, pbinding.host
                ports_obj.PortBinding.delete_objects(
                    admin_ctx, status=constants.INACTIVE, port_id=port_id)
                ports_obj.PortBindingLevel.delete_objects(
                    admin_ctx, port_id=port_id, host=host)

        if dup_pbindings:
            port_ids = [pbinding.port_id for pbinding in dup_pbindings]
            action = 'can be' if _dry_run else 'have been'
            LOG.info('The following duplicated PortBinding registers with '
                     'status=INACTIVE %s removed, port_ids: %s',
                     action, port_ids)
        else:
            LOG.info('No duplicated PortBinding registers has been found.')
