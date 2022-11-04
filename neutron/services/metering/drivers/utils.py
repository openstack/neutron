# Copyright 2017 Red Hat, Inc.
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

from neutron_lib.utils import runtime
from oslo_log import log as logging


LOG = logging.getLogger(__name__)

METERING_NAMESPACE = 'neutron.services.metering_drivers'


def load_metering_driver(plugin, conf):
    """Load metering driver

    :param plugin: the metering plugin
    :param conf: driver configuration object
    :raises SystemExit of 1 if driver cannot be loaded
    """

    try:
        loaded_class = runtime.load_class_by_alias_or_classname(
            METERING_NAMESPACE, conf.driver)
        return loaded_class(plugin, conf)
    except ImportError:
        LOG.error("Error loading metering driver '%s'", conf.driver)
        raise SystemExit(1)
