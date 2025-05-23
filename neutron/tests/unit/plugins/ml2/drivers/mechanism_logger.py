# Copyright (c) 2013 OpenStack Foundation
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

from neutron_lib.plugins.ml2 import api
from oslo_log import log


LOG = log.getLogger(__name__)


class LoggerMechanismDriver(api.MechanismDriver):
    """Mechanism driver that logs all calls and parameters made.

    Generally used for testing and debugging.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._supported_extensions = set()

    def initialize(self):
        pass

    def _log_diff_call(self, method_name, context):
        # On the delete the context.current item is the object with
        # all the info and the context.original is the delete object
        # In order to have the output format correct this swap is needed
        if "delete" in method_name:
            og_item = context.current if context.current else {}
            curr_item = context.original if context.original else {}
        else:
            og_item = context.original if context.original else {}
            curr_item = context.current if context.current else {}

        removed_keys = set(og_item.keys()) - set(curr_item.keys())
        added_keys = set(curr_item.keys()) - set(og_item.keys())
        output = f"{method_name}:\n"

        for k in curr_item.keys():
            if k in og_item and og_item[k] != curr_item[k]:
                output += "key[{}], {} -> {}\n".format(
                        k, og_item[k], curr_item[k])
        for add_k in added_keys:
            output += f"key[{add_k}], None -> {curr_item[add_k]}\n"
        for rem_k in removed_keys:
            output += f"key[{rem_k}], {og_item[rem_k]} -> None\n"

        LOG.debug(output)

    def _log_network_call(self, method_name, context):
        LOG.info("%(method)s called with network settings %(current)s "
                 "(original settings %(original)s) and "
                 "network segments %(segments)s",
                 {'method': method_name,
                  'current': context.current,
                  'original': context.original,
                  'segments': context.network_segments})

    def create_network_precommit(self, context):
        self._log_network_call("create_network_precommit", context)
        self._log_diff_call("create_network_precommit", context)

    def create_network_postcommit(self, context):
        self._log_network_call("create_network_postcommit", context)
        self._log_diff_call("create_network_postcommit", context)

    def update_network_precommit(self, context):
        self._log_network_call("update_network_precommit", context)
        self._log_diff_call("update_network_precommit", context)

    def update_network_postcommit(self, context):
        self._log_network_call("update_network_postcommit", context)
        self._log_diff_call("update_network_postcommit", context)

    def delete_network_precommit(self, context):
        self._log_network_call("delete_network_precommit", context)
        self._log_diff_call("delete_network_precommit", context)

    def delete_network_postcommit(self, context):
        self._log_network_call("delete_network_postcommit", context)
        self._log_diff_call("delete_network_postcommit", context)

    def check_vlan_transparency(self, context):
        self._log_network_call("check_vlan_transparency", context)
        self._log_diff_call("check_vlan_transparency", context)
        return True

    def check_vlan_qinq(self, context):
        self._log_network_call("check_vlan_qinq", context)
        self._log_diff_call("check_vlan_qinq", context)
        return True

    def _log_subnet_call(self, method_name, context):
        LOG.info("%(method)s called with subnet settings %(current)s "
                 "(original settings %(original)s)",
                 {'method': method_name,
                  'current': context.current,
                  'original': context.original})

    def create_subnet_precommit(self, context):
        self._log_subnet_call("create_subnet_precommit", context)
        self._log_diff_call("create_subnet_precommit", context)

    def create_subnet_postcommit(self, context):
        self._log_subnet_call("create_subnet_postcommit", context)
        self._log_diff_call("create_subnet_postcommit", context)

    def update_subnet_precommit(self, context):
        self._log_subnet_call("update_subnet_precommit", context)
        self._log_diff_call("update_subnet_precommit", context)

    def update_subnet_postcommit(self, context):
        self._log_subnet_call("update_subnet_postcommit", context)
        self._log_diff_call("update_subnet_postcommit", context)

    def delete_subnet_precommit(self, context):
        self._log_subnet_call("delete_subnet_precommit", context)
        self._log_diff_call("delete_subnet_precommit", context)

    def delete_subnet_postcommit(self, context):
        self._log_subnet_call("delete_subnet_postcommit", context)
        self._log_diff_call("delete_subnet_postcommit", context)

    def _log_port_call(self, method_name, context):
        network_context = context.network
        LOG.info("%(method)s called with port settings %(current)s "
                 "(original settings %(original)s) "
                 "host %(host)s "
                 "(original host %(original_host)s) "
                 "vif type %(vif_type)s "
                 "(original vif type %(original_vif_type)s) "
                 "vif details %(vif_details)s "
                 "(original vif details %(original_vif_details)s) "
                 "binding levels %(levels)s "
                 "(original binding levels %(original_levels)s) "
                 "on network %(network)s "
                 "with segments to bind %(segments_to_bind)s",
                 {'method': method_name,
                  'current': context.current,
                  'original': context.original,
                  'host': context.host,
                  'original_host': context.original_host,
                  'vif_type': context.vif_type,
                  'original_vif_type': context.original_vif_type,
                  'vif_details': context.vif_details,
                  'original_vif_details': context.original_vif_details,
                  'levels': context.binding_levels,
                  'original_levels': context.original_binding_levels,
                  'network': network_context.current,
                  'segments_to_bind': context.segments_to_bind})

    def create_port_precommit(self, context):
        self._log_port_call("create_port_precommit", context)
        self._log_diff_call("create_port_precommit", context)

    def create_port_postcommit(self, context):
        self._log_port_call("create_port_postcommit", context)
        self._log_diff_call("create_port_postcommit", context)

    def update_port_precommit(self, context):
        self._log_port_call("update_port_precommit", context)
        self._log_diff_call("update_port_precommit", context)

    def update_port_postcommit(self, context):
        self._log_port_call("update_port_postcommit", context)
        self._log_diff_call("update_port_postcommit", context)

    def delete_port_precommit(self, context):
        self._log_port_call("delete_port_precommit", context)
        self._log_diff_call("delete_port_precommit", context)

    def delete_port_postcommit(self, context):
        self._log_port_call("delete_port_postcommit", context)
        self._log_diff_call("delete_port_postcommit", context)

    def bind_port(self, context):
        self._log_port_call("bind_port", context)
        self._log_diff_call("bind_port", context)

    def filter_hosts_with_segment_access(
            self, context, segments, candidate_hosts, agent_getter):
        LOG.info("filter_hosts_with_segment_access called with segments "
                 "%(segments)s, candidate hosts %(hosts)s ",
                 {'segments': segments, 'hosts': candidate_hosts})
        return set()

    def supported_extensions(self, extensions):
        if self._supported_extensions:
            return extensions & self._supported_extensions
        return extensions
