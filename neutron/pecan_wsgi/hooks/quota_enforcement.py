# Copyright (c) 2015 Mirantis, Inc.
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

import collections

from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from oslo_log import log as logging
from pecan import hooks

from neutron import manager
from neutron import quota
from neutron.quota import resource_registry

LOG = logging.getLogger(__name__)


class QuotaEnforcementHook(hooks.PecanHook):

    priority = 130

    def before(self, state):
        collection = state.request.context.get('collection')
        resource = state.request.context.get('resource')
        items = state.request.context.get('resources')
        if state.request.method != 'POST' or not resource or not items:
            return
        plugin = manager.NeutronManager.get_plugin_for_resource(collection)
        # Store requested resource amounts grouping them by tenant
        deltas = collections.Counter(map(lambda x: x['tenant_id'], items))
        # Perform quota enforcement
        reservations = []
        neutron_context = state.request.context.get('neutron_context')
        for (tenant_id, delta) in deltas.items():
            try:
                reservation = quota.QUOTAS.make_reservation(
                    neutron_context,
                    tenant_id,
                    {resource: delta},
                    plugin)
                LOG.debug("Made reservation on behalf of %(tenant_id)s "
                          "for: %(delta)s",
                          {'tenant_id': tenant_id, 'delta': {resource: delta}})
                reservations.append(reservation)
            except exceptions.QuotaResourceUnknown as e:
                # Quotas cannot be enforced on this resource
                LOG.debug(e)
        # Save the reservations in the request context so that they can be
        # retrieved in the 'after' hook
        state.request.context['reservations'] = reservations

    def after(self, state):
        neutron_context = state.request.context.get('neutron_context')
        if not neutron_context:
            return
        collection = state.request.context.get('collection')
        resource = state.request.context.get('resource')
        if state.request.method == 'GET' and collection:
            # resync on list operations to preserve behavior of old API
            resource_registry.resync_resource(
                neutron_context, resource, neutron_context.tenant_id)
        # Commit reservation(s)
        reservations = state.request.context.get('reservations') or []
        if not reservations and state.request.method != 'DELETE':
            return
        with db_api.CONTEXT_WRITER.using(neutron_context):
            # Commit the reservation(s)
            for reservation in reservations:
                quota.QUOTAS.commit_reservation(
                    neutron_context, reservation.reservation_id)
            resource_registry.set_resources_dirty(neutron_context)
