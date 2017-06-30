# Copyright (c) 2016 IBM
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

import functools

from keystoneauth1 import exceptions as ks_exc
from keystoneauth1 import loading as ks_loading
from oslo_config import cfg

from neutron._i18n import _
from neutron.common import exceptions as n_exc

PLACEMENT_API_WITH_AGGREGATES = 'placement 1.1'


def check_placement_api_available(f):
    @functools.wraps(f)
    def wrapper(self, *a, **k):
        try:
            return f(self, *a, **k)
        except ks_exc.EndpointNotFound:
            raise n_exc.PlacementEndpointNotFound()
    return wrapper


class PlacementAPIClient(object):
    """Client class for placement ReST API."""

    ks_filter = {'service_type': 'placement',
                 'region_name': cfg.CONF.placement.region_name}

    def __init__(self):
        auth_plugin = ks_loading.load_auth_from_conf_options(
            cfg.CONF, 'placement')
        self._client = ks_loading.load_session_from_conf_options(
            cfg.CONF, 'placement', auth=auth_plugin)
        self._disabled = False

    def _get(self, url, **kwargs):
        return self._client.get(url, endpoint_filter=self.ks_filter,
                                **kwargs)

    def _post(self, url, data, **kwargs):
        return self._client.post(url, json=data,
                                 endpoint_filter=self.ks_filter, **kwargs)

    def _put(self, url, data, **kwargs):
        return self._client.put(url, json=data, endpoint_filter=self.ks_filter,
                                **kwargs)

    def _delete(self, url, **kwargs):
        return self._client.delete(url, endpoint_filter=self.ks_filter,
                                   **kwargs)

    @check_placement_api_available
    def create_resource_provider(self, resource_provider):
        """Create a resource provider.

        :param resource_provider: The resource provider
        :type resource_provider: dict: name (required), uuid (required)
        """
        url = '/resource_providers'
        self._post(url, resource_provider)

    @check_placement_api_available
    def delete_resource_provider(self, resource_provider_uuid):
        """Delete a resource provider.

        :param resource_provider_uuid: UUID of the resource provider
        :type resource_provider_uuid: str
        """
        url = '/resource_providers/%s' % resource_provider_uuid
        self._delete(url)

    @check_placement_api_available
    def create_inventory(self, resource_provider_uuid, inventory):
        """Create an inventory.

        :param resource_provider_uuid: UUID of the resource provider
        :type resource_provider_uuid: str
        :param inventory: The inventory
        :type inventory: dict: resource_class (required), total (required),
          reserved (required), min_unit (required), max_unit (required),
          step_size (required), allocation_ratio (required)
        """
        url = '/resource_providers/%s/inventories' % resource_provider_uuid
        self._post(url, inventory)

    @check_placement_api_available
    def get_inventory(self, resource_provider_uuid, resource_class):
        """Get resource provider inventory.

        :param resource_provider_uuid: UUID of the resource provider
        :type resource_provider_uuid: str
        :param resource_class: Resource class name of the inventory to be
          returned
        :type resource_class: str
        :raises n_exc.PlacementInventoryNotFound: For failure to find inventory
          for a resource provider
        """
        url = '/resource_providers/%s/inventories/%s' % (
            resource_provider_uuid, resource_class)
        try:
            return self._get(url).json()
        except ks_exc.NotFound as e:
            if "No resource provider with uuid" in e.details:
                raise n_exc.PlacementResourceProviderNotFound(
                    resource_provider=resource_provider_uuid)
            elif _("No inventory of class") in e.details:
                raise n_exc.PlacementInventoryNotFound(
                    resource_provider=resource_provider_uuid,
                    resource_class=resource_class)
            else:
                raise

    @check_placement_api_available
    def update_inventory(self, resource_provider_uuid, inventory,
                         resource_class):
        """Update an inventory.

        :param resource_provider_uuid: UUID of the resource provider
        :type resource_provider_uuid: str
        :param inventory: The inventory
        :type inventory: dict
        :param resource_class: The resource class of the inventory to update
        :type resource_class: str
        :raises n_exc.PlacementInventoryUpdateConflict: For failure to updste
          inventory due to outdated resource_provider_generation
        """
        url = '/resource_providers/%s/inventories/%s' % (
            resource_provider_uuid, resource_class)
        try:
            self._put(url, inventory)
        except ks_exc.Conflict:
            raise n_exc.PlacementInventoryUpdateConflict(
                resource_provider=resource_provider_uuid,
                resource_class=resource_class)

    @check_placement_api_available
    def associate_aggregates(self, resource_provider_uuid, aggregates):
        """Associate a list of aggregates with a resource provider.

        :param resource_provider_uuid: UUID of the resource provider
        :type resource_provider_uuid: str
        :param aggregates: aggregates to be associated to the resource provider
        :type aggregates: list of UUIDs
        """
        url = '/resource_providers/%s/aggregates' % resource_provider_uuid
        self._put(url, aggregates,
                 headers={'openstack-api-version':
                          PLACEMENT_API_WITH_AGGREGATES})

    @check_placement_api_available
    def list_aggregates(self, resource_provider_uuid):
        """List resource provider aggregates.

        :param resource_provider_uuid: UUID of the resource provider
        :type resource_provider_uuid: str
        """
        url = '/resource_providers/%s/aggregates' % resource_provider_uuid
        try:
            return self._get(
                url, headers={'openstack-api-version':
                              PLACEMENT_API_WITH_AGGREGATES}).json()
        except ks_exc.NotFound:
            raise n_exc.PlacementAggregateNotFound(
                resource_provider=resource_provider_uuid)
