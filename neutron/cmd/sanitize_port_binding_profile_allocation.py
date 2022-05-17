# Copyright (c) 2021 Ericsson Software Technology
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

from neutron_lib.api import converters
from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_config import cfg
from oslo_db import options as db_options
from oslo_log import log as logging

from neutron.common import config as common_config
from neutron.objects import ports as port_obj
from neutron.objects.qos import binding as qos_binding_obj
from neutron.objects.qos import rule as qos_rule_obj


LOG = logging.getLogger(__name__)


def setup_conf():
    conf = cfg.CONF
    common_config.register_common_config_options()
    db_group, neutron_db_opts = db_options.list_opts()[0]
    cfg.CONF.register_cli_opts(neutron_db_opts, db_group)
    conf()


def main():
    """Main method for sanitizing "ml2_port_bindings.profile" column.

    This script will sanitize "ml2_port_bindings.profile" columns existing in
    the database. In Yoga release the format of this column has changed from:
        {'allocation': '<rp_uuid>'}
    to:
        {'allocation': {'<group_uuid>': '<rp_uuid>'}}

    where group_uuid is generated based on port_id and ID of QoS rules
    belonging to that group.
    """
    setup_conf()
    admin_ctx = context.get_admin_context()
    with db_api.CONTEXT_WRITER.using(admin_ctx):
        for port_binding in port_obj.PortBinding.get_objects(admin_ctx):
            # NOTE(przszc): Before minimum packet rate rule was introduced,
            # binding-profile.allocation attribute could contain only a single
            # RP UUID, responsible for providing minimum bandwidth resources.
            # Because of that, whenever we find allocation attribute that still
            # uses old format, we can safely assume that we need to generate
            # minimum bandwidth group UUID.
            allocation = port_binding.profile.get('allocation')
            if (not allocation or isinstance(allocation, dict)):
                continue

            qos_port_binding = qos_binding_obj.QosPolicyPortBinding.get_object(
                admin_ctx, port_id=port_binding.port_id)
            if not qos_port_binding:
                LOG.error(
                    'Failed to sanitize binding-profile.allocation attribute '
                    '%s for port %s: Did not find associated QoS policy.',
                    allocation, port_binding.port_id)
                continue

            min_bw_rules = qos_rule_obj.QosMinimumBandwidthRule.get_objects(
                admin_ctx, qos_policy_id=qos_port_binding.policy_id)
            if not min_bw_rules:
                LOG.error(
                    'Failed to sanitize binding-profile.allocation attribute '
                    '%s for port %s: Associated QoS policy %s has no minimum '
                    'bandwidth rules.', allocation, port_binding.port_id,
                    qos_port_binding.policy_id)
                continue

            port_binding.profile = {'allocation':
                converters.convert_to_sanitized_binding_profile_allocation(
                    allocation, port_binding.port_id, min_bw_rules)}
            LOG.info('Port %s updated, New binding-profile.allocation format: '
                     '%s', port_binding.port_id, port_binding.profile)
            port_binding.update()
