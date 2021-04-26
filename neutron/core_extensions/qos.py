# Copyright (c) 2015 Red Hat Inc.
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

from neutron_lib.db import api as db_api
from neutron_lib.exceptions import qos as qos_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts

from neutron.core_extensions import base
from neutron.objects.qos import policy as policy_object


class QosCoreResourceExtension(base.CoreResourceExtension):

    @property
    def plugin_loaded(self):
        if not hasattr(self, '_plugin_loaded'):
            self._plugin_loaded = (
                plugin_constants.QOS in directory.get_plugins())
        return self._plugin_loaded

    def _check_policy_change_permission(self, context, old_policy):
        """An existing policy can be modified only if one of the following is
        true:

              the policy's tenant is the context's tenant
              the policy is shared with the tenant

        Using is_accessible expresses these conditions.
        """
        if not (policy_object.QosPolicy.is_accessible(context, old_policy)):
            raise qos_exc.PolicyRemoveAuthorizationError(
                policy_id=old_policy.id)

    def _update_port_policy(self, context, port, port_changes):
        old_policy = policy_object.QosPolicy.get_port_policy(
            context.elevated(), port['id'])
        if old_policy:
            self._check_policy_change_permission(context, old_policy)
            old_policy.detach_port(port['id'])

        qos_policy_id = port_changes.get(qos_consts.QOS_POLICY_ID)
        if qos_policy_id is not None:
            policy = policy_object.QosPolicy.get_policy_obj(
                context, qos_policy_id)
            policy.attach_port(port['id'])
        port[qos_consts.QOS_POLICY_ID] = qos_policy_id

    def _create_network_policy(self, context, network, network_changes):
        qos_policy_id = network_changes.get(qos_consts.QOS_POLICY_ID)
        if not qos_policy_id:
            policy_obj = policy_object.QosPolicyDefault.get_object(
                context, project_id=network['project_id'])
            if policy_obj is not None:
                qos_policy_id = policy_obj.qos_policy_id

        if qos_policy_id is not None:
            policy = policy_object.QosPolicy.get_policy_obj(
                context, qos_policy_id)
            policy.attach_network(network['id'])
        network[qos_consts.QOS_POLICY_ID] = qos_policy_id

    def _update_network_policy(self, context, network, network_changes):
        old_policy = policy_object.QosPolicy.get_network_policy(
            context.elevated(), network['id'])
        if old_policy:
            self._check_policy_change_permission(context, old_policy)
            old_policy.detach_network(network['id'])

        qos_policy_id = network_changes.get(qos_consts.QOS_POLICY_ID)
        if qos_policy_id is not None:
            policy = policy_object.QosPolicy.get_policy_obj(
                context, qos_policy_id)
            policy.attach_network(network['id'])
        network[qos_consts.QOS_POLICY_ID] = qos_policy_id

    def _exec(self, method_name, context, kwargs):
        with db_api.CONTEXT_WRITER.using(context):
            return getattr(self, method_name)(context=context, **kwargs)

    def process_fields(self, context, resource_type, event_type,
                       requested_resource, actual_resource):
        if (qos_consts.QOS_POLICY_ID in requested_resource and
                self.plugin_loaded):
            method_name = ('_%(event)s_%(resource)s_policy' %
                           {'event': event_type, 'resource': resource_type})
            self._exec(method_name, context,
                       {resource_type: actual_resource,
                        "%s_changes" % resource_type: requested_resource})

    def extract_fields(self, resource_type, resource):
        if not self.plugin_loaded:
            return {}

        binding = resource['qos_policy_binding']
        qos_policy_id = binding['policy_id'] if binding else None
        retval = {qos_consts.QOS_POLICY_ID: qos_policy_id}
        if resource_type == base.PORT:
            network_binding = resource.get('qos_network_policy_binding')
            qos_net_policy_id = (network_binding['policy_id'] if
                                 network_binding else None)
            retval[qos_consts.QOS_NETWORK_POLICY_ID] = qos_net_policy_id
        return retval
