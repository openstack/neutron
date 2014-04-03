# Copyright (c) 2014 OpenStack Foundation
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

from neutron.common import log
from neutron.openstack.common import log
from neutron.plugins.grouppolicy import group_policy_driver_api as api


LOG = log.getLogger(__name__)


class NoopDriver(api.PolicyDriver):

    @log.log
    def initialize(self):
        pass

    @log.log
    def create_endpoint_precommit(self, context):
        pass

    @log.log
    def create_endpoint_postcommit(self, context):
        pass

    @log.log
    def update_endpoint_precommit(self, context):
        pass

    @log.log
    def update_endpoint_postcommit(self, context):
        pass

    @log.log
    def delete_endpoint_precommit(self, context):
        pass

    @log.log
    def delete_endpoint_postcommit(self, context):
        pass

    @log.log
    def create_endpoint_group_precommit(self, context):
        pass

    @log.log
    def create_endpoint_group_postcommit(self, context):
        pass

    @log.log
    def update_endpoint_group_precommit(self, context):
        pass

    @log.log
    def update_endpoint_group_postcommit(self, context):
        pass

    @log.log
    def delete_endpoint_group_precommit(self, context):
        pass

    @log.log
    def delete_endpoint_group_postcommit(self, context):
        pass
