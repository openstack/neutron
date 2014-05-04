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
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.grouppolicy import group_policy_driver_api as api


LOG = logging.getLogger(__name__)


class MappingDriver(api.PolicyDriver):

    @log.log
    def initialize(self):
        LOG.info("initialize")

    @log.log
    def create_endpoint_precommit(self, context):
        LOG.info("create_endpoint_precommit: %s", context.current)

    @log.log
    def create_endpoint_postcommit(self, context):
        LOG.info("create_endpoint_postcommit: %s", context.current)

    @log.log
    def update_endpoint_precommit(self, context):
        pass

    @log.log
    def update_endpoint_postcommit(self, context):
        pass

    @log.log
    def delete_endpoint_precommit(self, context):
        LOG.info("delete_endpoint_precommit: %s", context.current)

    @log.log
    def delete_endpoint_postcommit(self, context):
        LOG.info("delete_endpoint_postcommit: %s", context.current)

    @log.log
    def create_endpoint_group_precommit(self, context):
        LOG.info("create_endpoint_group_precommit: %s", context.current)

    @log.log
    def create_endpoint_group_postcommit(self, context):
        LOG.info("create_endpoint_group_postcommit: %s", context.current)

    @log.log
    def update_endpoint_group_precommit(self, context):
        pass

    @log.log
    def update_endpoint_group_postcommit(self, context):
        pass

    @log.log
    def delete_endpoint_group_precommit(self, context):
        LOG.info("delete_endpoint_group_precommit: %s", context.current)

    @log.log
    def delete_endpoint_group_postcommit(self, context):
        LOG.info("delete_endpoint_group_postcommit: %s", context.current)

    @log.log
    def create_bridge_domain_precommit(self, context):
        LOG.info("create_bridge_domain_precommit: %s", context.current)
        if context.current['neutron_network_id']:
            self._validate_bd_network(context)

    @log.log
    def create_bridge_domain_postcommit(self, context):
        LOG.info("create_bridge_domain_postcommit: %s", context.current)
        if not context.current['neutron_network_id']:
            self._create_bd_network(context)

    @log.log
    def update_bridge_domain_precommit(self, context):
        pass

    @log.log
    def update_bridge_domain_postcommit(self, context):
        pass

    @log.log
    def delete_bridge_domain_precommit(self, context):
        LOG.info("delete_bridge_domain_precommit: %s", context.current)

    @log.log
    def delete_bridge_domain_postcommit(self, context):
        LOG.info("delete_bridge_domain_postcommit: %s", context.current)

    @log.log
    def create_routing_domain_precommit(self, context):
        LOG.info("create_routing_domain_precommit: %s", context.current)
        if context.current['neutron_routers']:
            self._validate_rd_routers(context)

    @log.log
    def create_routing_domain_postcommit(self, context):
        LOG.info("create_routing_domain_postcommit: %s", context.current)
        if not context.current['neutron_routers']:
            self._create_rd_routers(context)

    @log.log
    def update_routing_domain_precommit(self, context):
        pass

    @log.log
    def update_routing_domain_postcommit(self, context):
        pass

    @log.log
    def delete_routing_domain_precommit(self, context):
        LOG.info("delete_routing_domain_precommit: %s", context.current)

    @log.log
    def delete_routing_domain_postcommit(self, context):
        LOG.info("delete_routing_domain_postcommit: %s", context.current)

    def _validate_rd_routers(self, context):
        # TODO(rkukura): Implement
        pass

    def _create_rd_routers(self, context):
        # TODO(rkukura): Implement
        pass

    def _validate_bd_network(self, context):
        # TODO(rkukura): Implement
        pass

    def _create_bd_network(self, context):
        attrs = {'network':
                 {'tenant_id': context.current['id'],
                  'name': 'bd_' + context.current['name'],
                  'admin_state_up': True,
                  'shared': False}}
        core_plugin = manager.NeutronManager.get_plugin()
        network = core_plugin.create_network(context._plugin_context, attrs)
        context.set_neutron_network_id(network['id'])
