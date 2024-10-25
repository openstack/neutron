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

import abc

from oslo_config import cfg

BASE_ROUTER_TRAFFIC_COUNTER_KEY = "router-"
BASE_PROJECT_TRAFFIC_COUNTER_KEY = "project-"
BASE_LABEL_TRAFFIC_COUNTER_KEY = "label-"


class MeteringAbstractDriver(metaclass=abc.ABCMeta):
    """Abstract Metering driver."""

    def __init__(self, plugin, conf):
        self.conf = conf or cfg.CONF
        self.plugin = plugin

        self.granular_traffic_data = self.conf.granular_traffic_data

    @abc.abstractmethod
    def update_routers(self, context, routers):
        pass

    @abc.abstractmethod
    def remove_router(self, context, router_id):
        pass

    @abc.abstractmethod
    def update_metering_label_rules(self, context, routers):
        pass

    @abc.abstractmethod
    def add_metering_label(self, context, routers):
        pass

    @abc.abstractmethod
    def remove_metering_label(self, context, routers):
        pass

    @abc.abstractmethod
    def get_traffic_counters(self, context, routers):
        pass

    @abc.abstractmethod
    def sync_router_namespaces(self, context, routers):
        pass

    @staticmethod
    def get_router_traffic_counter_key(router_id):
        return MeteringAbstractDriver._concat_base_key_with_id(
            router_id, BASE_ROUTER_TRAFFIC_COUNTER_KEY)

    @staticmethod
    def get_project_traffic_counter_key(project_id):
        return MeteringAbstractDriver._concat_base_key_with_id(
            project_id, BASE_PROJECT_TRAFFIC_COUNTER_KEY)

    @staticmethod
    def get_label_traffic_counter_key(label_id):
        return MeteringAbstractDriver._concat_base_key_with_id(
            label_id, BASE_LABEL_TRAFFIC_COUNTER_KEY)

    @staticmethod
    def _concat_base_key_with_id(resource_id, base_traffic_key):
        return base_traffic_key + "%s" % resource_id
