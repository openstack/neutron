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

from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context


class TestMechanismDriver(api.MechanismDriver):
    """Test mechanism driver for testing mechanism driver api."""

    def initialize(self):
        pass

    def _check_network_context(self, context, original_expected):
        assert(isinstance(context, driver_context.NetworkContext))
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
        assert(isinstance(context, driver_context.SubnetContext))
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
        assert(isinstance(context, driver_context.PortContext))
        assert(isinstance(context.current, dict))
        assert(context.current['id'] is not None)
        if original_expected:
            assert(isinstance(context.original, dict))
            assert(context.current['id'] == context.original['id'])
        else:
            assert(not context.original)
        network_context = context.network
        assert(isinstance(network_context, driver_context.NetworkContext))
        self._check_network_context(network_context, False)

    def create_port_precommit(self, context):
        self._check_port_context(context, False)

    def create_port_postcommit(self, context):
        self._check_port_context(context, False)

    def update_port_precommit(self, context):
        self._check_port_context(context, True)

    def update_port_postcommit(self, context):
        self._check_port_context(context, True)

    def delete_port_precommit(self, context):
        self._check_port_context(context, False)

    def delete_port_postcommit(self, context):
        self._check_port_context(context, False)
