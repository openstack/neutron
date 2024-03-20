# Copyright 2024 Red Hat, Inc.
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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import priority_group
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources

from neutron.common.ovn import utils
from neutron.db import l3_attrs_db


@registry.has_registry_receivers
class OVN_L3_HA_db_mixin(l3_attrs_db.ExtraAttributesMixin):
    """Mixin class to add high availability capability to OVN routers."""

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_CREATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _precommit_router_create(self, resource, event, trigger, payload):
        """Event handler to set ha flag creation."""
        # NOTE(ralonsoh): OVN L3 router HA flag is mandatory and True always,
        # enforced by ``OvnDriver.ha_support`` set to ``MANDATORY``. This flag
        # cannot be updated.
        router = payload.latest_state
        if not utils.is_ovn_provider_router(router):
            return
        router_db = payload.metadata['router_db']
        self.set_extra_attr_value(router_db, 'ha', True)
