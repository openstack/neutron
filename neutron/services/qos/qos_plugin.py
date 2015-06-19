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

from neutron.extensions import qos


class QoSPlugin(qos.QoSPluginBase):
    """Implementation of the Neutron QoS Service Plugin.

    This class implements a Quality of Service plugin that
    provides quality of service parameters over ports and
    networks.

    """
    supported_extension_aliases = ['qos']

    def __init__(self):
        super(QoSPlugin, self).__init__()
        #self.register_rpc()
        #self.register_port_callbacks()
        #self.register_net_callbacks()

    def register_rpc(self):
        # RPC support
        # TODO(ajo): register ourselves to the generic RPC framework
        #            so we will provide QoS information for ports and
        #            networks.
        pass

    def register_port_callbacks(self):
        # TODO(qos): Register the callbacks to properly manage
        #            extension of resources
        pass

    def register_net_callbacks(self):
        # TODO(qos): Register the callbacks to properly manage
        #            extension of resources
        pass

    def create_qos_policy(self, context, qos_policy):
        pass

    def update_qos_policy(self, context, qos_policy_id, qos_policy):
        pass

    def delete_qos_policy(self, context, qos_policy_id):
        pass

    def get_qos_policy(self, context, qos_policy_id, fields=None):
        pass

    def get_qos_policies(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        pass

    def create_qos_bandwidth_limit_rule(self, context,
                                        qos_bandwidthlimit_rule):
        pass

    def update_qos_bandwidth_limit_rule(self, context, rule_id, rule):
        pass

    def get_qos_bandwidth_limit_rule(self, context, rule_id, fields=None):
        pass

    def delete_qos_bandwith_limit_rule(self, context, rule_id):
        pass

    def get_qos_bandwith_limit_rules(self, context, filters=None, fields=None,
                                    sorts=None, limit=None, marker=None,
                                    page_reverse=False):
        pass
