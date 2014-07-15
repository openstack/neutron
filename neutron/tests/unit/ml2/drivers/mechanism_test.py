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

from neutron.common import constants as const
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_api as api


class TestMechanismDriver(api.MechanismDriver):
    """Test mechanism driver for testing mechanism driver api."""

    def initialize(self):
        self.bound_ports = set()

    def _check_network_context(self, context, original_expected):
        assert(isinstance(context, api.NetworkContext))
        assert(isinstance(context.current, dict))
        assert(context.current['id'] is not None)
        if original_expected:
            assert(isinstance(context.original, dict))
            assert(context.current['id'] == context.original['id'])
        else:
            assert(not context.original)
        assert(context.network_segments)

    def create_network_precommit(self, context):
        self._check_network_context(context, False)

    def create_network_postcommit(self, context):
        self._check_network_context(context, False)

    def update_network_precommit(self, context):
        self._check_network_context(context, True)

    def update_network_postcommit(self, context):
        self._check_network_context(context, True)

    def delete_network_precommit(self, context):
        self._check_network_context(context, False)

    def delete_network_postcommit(self, context):
        self._check_network_context(context, False)

    def _check_subnet_context(self, context, original_expected):
        assert(isinstance(context, api.SubnetContext))
        assert(isinstance(context.current, dict))
        assert(context.current['id'] is not None)
        if original_expected:
            assert(isinstance(context.original, dict))
            assert(context.current['id'] == context.original['id'])
        else:
            assert(not context.original)

    def create_subnet_precommit(self, context):
        self._check_subnet_context(context, False)

    def create_subnet_postcommit(self, context):
        self._check_subnet_context(context, False)

    def update_subnet_precommit(self, context):
        self._check_subnet_context(context, True)

    def update_subnet_postcommit(self, context):
        self._check_subnet_context(context, True)

    def delete_subnet_precommit(self, context):
        self._check_subnet_context(context, False)

    def delete_subnet_postcommit(self, context):
        self._check_subnet_context(context, False)

    def _check_port_context(self, context, original_expected):
        assert(isinstance(context, api.PortContext))
        assert(isinstance(context.current, dict))
        assert(context.current['id'] is not None)

        vif_type = context.current.get(portbindings.VIF_TYPE)
        assert(vif_type is not None)

        if vif_type in (portbindings.VIF_TYPE_UNBOUND,
                        portbindings.VIF_TYPE_BINDING_FAILED):
            assert(context.bound_segment is None)
            assert(context.bound_driver is None)
            assert(context.current['id'] not in self.bound_ports)
        else:
            assert(isinstance(context.bound_segment, dict))
            assert(context.bound_driver == 'test')
            assert(context.current['id'] in self.bound_ports)

        if original_expected:
            assert(isinstance(context.original, dict))
            assert(context.current['id'] == context.original['id'])
            vif_type = context.original.get(portbindings.VIF_TYPE)
            assert(vif_type is not None)
            if vif_type in (portbindings.VIF_TYPE_UNBOUND,
                            portbindings.VIF_TYPE_BINDING_FAILED):
                assert(context.original_bound_segment is None)
                assert(context.original_bound_driver is None)
            else:
                assert(isinstance(context.original_bound_segment, dict))
                assert(context.original_bound_driver == 'test')
        else:
            assert(context.original is None)
            assert(context.original_bound_segment is None)
            assert(context.original_bound_driver is None)

        network_context = context.network
        assert(isinstance(network_context, api.NetworkContext))
        self._check_network_context(network_context, False)

    def create_port_precommit(self, context):
        self._check_port_context(context, False)

    def create_port_postcommit(self, context):
        self._check_port_context(context, False)

    def update_port_precommit(self, context):
        if (context.original_bound_driver == 'test' and
            context.bound_driver != 'test'):
            self.bound_ports.remove(context.original['id'])
        self._check_port_context(context, True)

    def update_port_postcommit(self, context):
        self._check_port_context(context, True)

    def delete_port_precommit(self, context):
        self._check_port_context(context, False)

    def delete_port_postcommit(self, context):
        self._check_port_context(context, False)

    def bind_port(self, context):
        self._check_port_context(context, False)

        host = context.current.get(portbindings.HOST_ID, None)
        segment = context.network.network_segments[0][api.ID]
        if host == "host-ovs-no_filter":
            context.set_binding(segment, portbindings.VIF_TYPE_OVS,
                                {portbindings.CAP_PORT_FILTER: False})
            self.bound_ports.add(context.current['id'])
        elif host == "host-bridge-filter":
            context.set_binding(segment, portbindings.VIF_TYPE_BRIDGE,
                                {portbindings.CAP_PORT_FILTER: True})
            self.bound_ports.add(context.current['id'])
        elif host == "host-ovs-filter-active":
            context.set_binding(segment, portbindings.VIF_TYPE_OVS,
                                {portbindings.CAP_PORT_FILTER: True},
                                status=const.PORT_STATUS_ACTIVE)
            self.bound_ports.add(context.current['id'])
