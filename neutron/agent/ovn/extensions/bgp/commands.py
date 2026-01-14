# Copyright 2025 Red Hat, Inc.
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

from ovsdbapp.backend.ovs_idl import command as ovs_cmd

from neutron.services.bgp import constants


class SetChassisBgpBridgesCommand(ovs_cmd.BaseCommand):
    def __init__(self, api, chassis_name, bridge_name_list):
        super().__init__(api)
        self.chassis_name = chassis_name
        self.bridge_name_list = bridge_name_list

    def run_idl(self, txn):
        chassis = self.api.lookup('Chassis_Private', self.chassis_name)
        external_ids = chassis.external_ids
        external_ids[constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY] = ','.join(
            sorted(self.bridge_name_list))

        self.set_column(chassis, 'external_ids', external_ids)
