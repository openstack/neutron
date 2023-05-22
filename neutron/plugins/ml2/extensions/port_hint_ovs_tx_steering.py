# Copyright 2023 Ericsson Software Technology
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

from neutron_lib.plugins.ml2 import api
from oslo_log import log as logging

from neutron_lib.api.definitions import port_hint_ovs_tx_steering \
    as phint_txs_def


LOG = logging.getLogger(__name__)


class PortHintOvsTxSteeringExtensionDriver(api.ExtensionDriver):

    _supported_extension_alias = phint_txs_def.ALIAS

    def initialize(self):
        LOG.info(
            'PortHintOvsTxSteeringExtensionDriver initialization complete')

    @property
    def extension_alias(self):
        return self._supported_extension_alias
