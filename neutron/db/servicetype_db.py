# Copyright 2013 OpenStack Foundation.
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

from itertools import chain

from oslo_log import log as logging

from neutron.objects import servicetype as servicetype_obj
from neutron.services import provider_configuration as pconf

LOG = logging.getLogger(__name__)


class ServiceTypeManager(object):
    """Manage service type objects in Neutron."""

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.config = {}

    def add_provider_configuration(self, service_type, configuration):
        """Add or update the provider configuration for the service type."""
        LOG.debug('Adding provider configuration for service %s', service_type)
        self.config.update({service_type: configuration})

    def get_service_providers(self, context, filters=None, fields=None):
        if filters and 'service_type' in filters:
            return list(chain.from_iterable(
                self.config[svc_type].get_service_providers(filters, fields)
                for svc_type in filters['service_type']
                if svc_type in self.config))
        return list(
            chain.from_iterable(
                self.config[p].get_service_providers(filters, fields)
                for p in self.config)
        )

    def get_default_service_provider(self, context, service_type):
        """Return the default provider for a given service type."""
        filters = {'service_type': [service_type],
                   'default': [True]}
        providers = self.get_service_providers(context, filters=filters)
        # By construction we expect at most a single item in provider
        if not providers:
            raise pconf.DefaultServiceProviderNotFound(
                service_type=service_type
            )
        return providers[0]

    def get_provider_names_by_resource_ids(self, context, resource_ids):
        objs = servicetype_obj.ProviderResourceAssociation.get_objects(
            context, resource_id=resource_ids)
        return {rec.resource_id: rec.provider_name for rec in objs}

    def add_resource_association(self, context, service_type, provider_name,
                                 resource_id, expire_session=True):
        r = self.get_service_providers(context,
                                       filters={'service_type': [service_type],
                                                'name': [provider_name]})
        if not r:
            raise pconf.ServiceProviderNotFound(provider=provider_name,
                                                service_type=service_type)

        # we don't actually need service type for association.
        # resource_id is unique and belongs to specific service
        # which knows its type
        servicetype_obj.ProviderResourceAssociation(
            context, provider_name=provider_name,
            resource_id=resource_id).create()
        # NOTE(blogan): the ProviderResourceAssociation relationship will not
        # be populated if a resource was created before this.  The expire_all
        # will force the session to go retrieve the new data when that
        # resource will be read again.  It has been suggested that we can
        # crawl through everything in the mapper to find the resource with
        # the ID that matches resource_id and expire that one, but we can
        # just start with this.
        # NOTE(ralonsoh): to be removed once the new engine facade is fully
        # implanted in Neutron.
        if expire_session:
            context.session.expire_all()

    def del_resource_associations(self, context, resource_ids):
        if not resource_ids:
            return
        servicetype_obj.ProviderResourceAssociation.delete_objects(
            context, resource_id=resource_ids)
