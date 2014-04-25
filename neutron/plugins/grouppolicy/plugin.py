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

from neutron.common import log
from neutron.db import api as qdbapi
from neutron.db.grouppolicy import db_group_policy_mapping
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.grouppolicy.common import exceptions as gp_exc
from neutron.plugins.grouppolicy import config  # noqa
from neutron.plugins.grouppolicy import group_policy_context as p_context
from neutron.plugins.grouppolicy import policy_driver_manager as manager


LOG = logging.getLogger(__name__)


class GroupPolicyPlugin(db_group_policy_mapping.GroupPolicyMappingDbMixin):

    """Implementation of the Group Policy Model Plugin.

    This class manages the workflow of Group Policy request/response.
    Most DB related works are implemented in class
    db_group_policy_mapping.GroupPolicyMappingDbMixin.
    """
    supported_extension_aliases = ["group-policy", "group-policy-mapping"]

    def __init__(self):
        qdbapi.register_models()
        self.policy_driver_manager = manager.PolicyDriverManager()
        super(GroupPolicyPlugin, self).__init__()
        self.policy_driver_manager.initialize()

    @log.log
    def create_endpoint(self, context, endpoint):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin, self).create_endpoint(context,
                                                                    endpoint)
            policy_context = p_context.EndpointContext(self, context, result)
            self.policy_driver_manager.create_endpoint_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_endpoint_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("policy_driver_manager.create_endpoint_postcommit "
                            "failed, deleting endpoint '%s'"), result['id'])
                self.delete_endpoint(context, result['id'])

        return result

    @log.log
    def update_endpoint(self, context, id, endpoint):
        session = context.session
        with session.begin(subtransactions=True):
            original_endpoint = super(GroupPolicyPlugin,
                                      self).get_endpoint(context, id)
            updated_endpoint = super(GroupPolicyPlugin,
                                     self).update_endpoint(context, id,
                                                           endpoint)
            policy_context = p_context.EndpointContext(
                self, context, updated_endpoint,
                original_endpoint=original_endpoint)
            self.policy_driver_manager.update_endpoint_precommit(
                policy_context)

        self.policy_driver_manager.update_endpoint_postcommit(policy_context)
        return updated_endpoint

    @log.log
    def delete_endpoint(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            endpoint = self.get_endpoint(context, id)
            policy_context = p_context.EndpointContext(self, context, endpoint)
            self.policy_driver_manager.create_endpoint_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_endpoint(context, id)

        try:
            self.policy_driver_manager.delete_endpoint_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("policy_driver_manager.delete_endpoint_postcommit "
                            "failed, deleting endpoint '%s'"), id)

    @log.log
    def create_endpoint_group(self, context, endpoint_group):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_endpoint_group(context, endpoint_group)
            policy_context = p_context.EndpointContext(self, context, result)
            self.policy_driver_manager.create_endpoint_group_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_endpoint_group_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_endpoint_group_postcommit "
                    "failed, deleting endpoint_group '%s'"), result['id'])
                self.delete_endpoint_group(context, result['id'])

        return result

    @log.log
    def update_endpoint_group(self, context, id, endpoint_group):
        session = context.session
        with session.begin(subtransactions=True):
            original_endpoint_group = super(GroupPolicyPlugin,
                                            self).get_endpoint_group(
                                                context, id)
            updated_endpoint_group = super(GroupPolicyPlugin,
                                           self).update_endpoint_group(
                                               context, id, endpoint_group)
            policy_context = p_context.EndpointContext(
                self, context, updated_endpoint_group,
                original_endpoint_group=original_endpoint_group)
            self.policy_driver_manager.update_endpoint_group_precommit(
                policy_context)

        self.policy_driver_manager.update_endpoint_group_postcommit(
            policy_context)

        return updated_endpoint_group

    @log.log
    def delete_endpoint_group(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            endpoint_group = self.get_endpoint_group(context, id)
            # TODO(sumit) : Do not delete if EPG has EPs
            policy_context = p_context.EndpointContext(self, context,
                                                       endpoint_group)
            self.policy_driver_manager.create_endpoint_group_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_endpoint_group(context, id)

        try:
            self.policy_driver_manager.delete_endpoint_group_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.delete_endpoint_group_postcommit "
                    "failed, deleting endpoint_group '%s'"), id)

    @log.log
    def create_bridge_domain(self, context, bridge_domain):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_bridge_domain(context, bridge_domain)
            policy_context = p_context.BridgeDomainContext(self, context,
                                                           result)
            self.policy_driver_manager.create_bridge_domain_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_bridge_domain_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_bridge_domain_postcommit "
                    "failed, deleting bridge_domain '%s'"), result['id'])
                self.delete_bridge_domain(context, result['id'])

        return result

    @log.log
    def update_bridge_domain(self, context, id, bridge_domain):
        session = context.session
        with session.begin(subtransactions=True):
            original_bridge_domain = super(GroupPolicyPlugin,
                                           self).get_bridge_domain(context, id)
            updated_bridge_domain = super(GroupPolicyPlugin,
                                          self).update_bridge_domain(
                                              context, id, bridge_domain)
            policy_context = p_context.BridgeDomainContext(
                self, context, updated_bridge_domain,
                original_bridge_domain=original_bridge_domain)
            self.policy_driver_manager.update_bridge_domain_precommit(
                policy_context)

        self.policy_driver_manager.update_bridge_domain_postcommit(
            policy_context)
        return updated_bridge_domain

    @log.log
    def delete_bridge_domain(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            bridge_domain = self.get_bridge_domain(context, id)
            policy_context = p_context.BridgeDomainContext(self, context,
                                                           bridge_domain)
            self.policy_driver_manager.create_bridge_domain_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_bridge_domain(context, id)

        try:
            self.policy_driver_manager.delete_bridge_domain_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.delete_bridge_domain_postcommit "
                    " failed, deleting bridge_domain '%s'"), id)

    @log.log
    def create_routing_domain(self, context, routing_domain):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(GroupPolicyPlugin,
                           self).create_routing_domain(context, routing_domain)
            policy_context = p_context.RoutingDomainContext(self, context,
                                                            result)
            self.policy_driver_manager.create_routing_domain_precommit(
                policy_context)

        try:
            self.policy_driver_manager.create_routing_domain_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.create_routing_domain_postcommit "
                    "failed, deleting routing_domain '%s'"), result['id'])
                self.delete_routing_domain(context, result['id'])

        return result

    @log.log
    def update_routing_domain(self, context, id, routing_domain):
        session = context.session
        with session.begin(subtransactions=True):
            original_routing_domain = super(GroupPolicyPlugin,
                                            self).get_routing_domain(
                                                context, id)
            updated_routing_domain = super(
                GroupPolicyPlugin, self).update_routing_domain(context, id,
                                                               routing_domain)
            policy_context = p_context.RoutingDomainContext(
                self, context, updated_routing_domain,
                original_routing_domain=original_routing_domain)
            self.policy_driver_manager.update_routing_domain_precommit(
                policy_context)

        self.policy_driver_manager.update_routing_domain_postcommit(
            policy_context)
        return updated_routing_domain

    @log.log
    def delete_routing_domain(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            routing_domain = self.get_routing_domain(context, id)
            policy_context = p_context.RoutingDomainContext(self, context,
                                                            routing_domain)
            self.policy_driver_manager.create_routing_domain_precommit(
                policy_context)
            super(GroupPolicyPlugin, self).delete_routing_domain(context, id)

        try:
            self.policy_driver_manager.delete_routing_domain_postcommit(
                policy_context)
        except gp_exc.GroupPolicyDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_(
                    "policy_driver_manager.delete_routing_domain_postcommit "
                    " failed, deleting routing_domain '%s'"), id)
