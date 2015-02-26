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

from oslo_log import log as logging
import sqlalchemy as sa

from neutron.db import model_base
from neutron.services import provider_configuration as pconf

LOG = logging.getLogger(__name__)


class ProviderResourceAssociation(model_base.BASEV2):
    provider_name = sa.Column(sa.String(255),
                              nullable=False, primary_key=True)
    # should be manually deleted on resource deletion
    resource_id = sa.Column(sa.String(36), nullable=False, primary_key=True,
                            unique=True)


class ServiceTypeManager(object):
    """Manage service type objects in Neutron."""

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._load_conf()

    def _load_conf(self):
        self.conf = pconf.ProviderConfiguration(
            pconf.parse_service_provider_opt())

    def get_service_providers(self, context, filters=None, fields=None):
        return self.conf.get_service_providers(filters, fields)

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

    def add_resource_association(self, context, service_type, provider_name,
                                 resource_id):
        r = self.conf.get_service_providers(
            filters={'service_type': [service_type], 'name': [provider_name]})
        if not r:
            raise pconf.ServiceProviderNotFound(provider=provider_name,
                                                service_type=service_type)

        with context.session.begin(subtransactions=True):
            # we don't actually need service type for association.
            # resource_id is unique and belongs to specific service
            # which knows its type
            assoc = ProviderResourceAssociation(provider_name=provider_name,
                                                resource_id=resource_id)
            context.session.add(assoc)

    def del_resource_associations(self, context, resource_ids):
        if not resource_ids:
            return
        with context.session.begin(subtransactions=True):
            (context.session.query(ProviderResourceAssociation).
             filter(
                 ProviderResourceAssociation.resource_id.in_(resource_ids)).
             delete(synchronize_session='fetch'))
