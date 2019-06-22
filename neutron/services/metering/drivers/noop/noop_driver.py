# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import helpers as log_helpers

from neutron.services.metering.drivers import abstract_driver


class NoopMeteringDriver(abstract_driver.MeteringAbstractDriver):

    @log_helpers.log_method_call
    def update_routers(self, context, routers):
        pass

    @log_helpers.log_method_call
    def remove_router(self, context, router_id):
        pass

    @log_helpers.log_method_call
    def update_metering_label_rules(self, context, routers):
        pass

    @log_helpers.log_method_call
    def add_metering_label_rule(self, context, routers):
        pass

    @log_helpers.log_method_call
    def remove_metering_label_rule(self, context, routers):
        pass

    @log_helpers.log_method_call
    def add_metering_label(self, context, routers):
        pass

    @log_helpers.log_method_call
    def remove_metering_label(self, context, routers):
        pass

    @log_helpers.log_method_call
    def get_traffic_counters(self, context, routers):
        pass

    @log_helpers.log_method_call
    def sync_router_namespaces(self, context, routers):
        pass
