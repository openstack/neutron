# Copyright 2012 OpenStack Foundation
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

from neutron.tests.tempest.common import cred_provider
from neutron.tests.tempest import config
from neutron.tests.tempest import manager
from neutron.tests.tempest.services.identity.v2.json.identity_client import \
    IdentityClientJSON
from neutron.tests.tempest.services.identity.v2.json.token_client import \
     TokenClientJSON
from neutron.tests.tempest.services.identity.v3.json.credentials_client \
     import CredentialsClientJSON
from neutron.tests.tempest.services.identity.v3.json.endpoints_client import \
    EndPointClientJSON
from neutron.tests.tempest.services.identity.v3.json.identity_client import \
    IdentityV3ClientJSON
from neutron.tests.tempest.services.identity.v3.json.policy_client import \
     PolicyClientJSON
from neutron.tests.tempest.services.identity.v3.json.region_client import \
     RegionClientJSON
from neutron.tests.tempest.services.identity.v3.json.service_client import \
    ServiceClientJSON
from neutron.tests.tempest.services.identity.v3.json.token_client import \
     V3TokenClientJSON
from neutron.tests.tempest.services.network.json.network_client import \
     NetworkClientJSON


CONF = config.CONF
LOG = logging.getLogger(__name__)


class Manager(manager.Manager):

    """
    Top level manager for OpenStack tempest clients
    """

    default_params = {
        'disable_ssl_certificate_validation':
            CONF.identity.disable_ssl_certificate_validation,
        'ca_certs': CONF.identity.ca_certificates_file,
        'trace_requests': CONF.debug.trace_requests
    }

    # NOTE: Tempest uses timeout values of compute API if project specific
    # timeout values don't exist.
    default_params_with_timeout_values = {
        'build_interval': CONF.compute.build_interval,
        'build_timeout': CONF.compute.build_timeout
    }
    default_params_with_timeout_values.update(default_params)

    def __init__(self, credentials=None, service=None):
        super(Manager, self).__init__(credentials=credentials)

        self._set_identity_clients()

        self.network_client = NetworkClientJSON(
            self.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **self.default_params)

    def _set_identity_clients(self):
        params = {
            'service': CONF.identity.catalog_type,
            'region': CONF.identity.region,
            'endpoint_type': 'adminURL'
        }
        params.update(self.default_params_with_timeout_values)

        self.identity_client = IdentityClientJSON(self.auth_provider,
                                                  **params)
        self.identity_v3_client = IdentityV3ClientJSON(self.auth_provider,
                                                       **params)
        self.endpoints_client = EndPointClientJSON(self.auth_provider,
                                                   **params)
        self.service_client = ServiceClientJSON(self.auth_provider, **params)
        self.policy_client = PolicyClientJSON(self.auth_provider, **params)
        self.region_client = RegionClientJSON(self.auth_provider, **params)
        self.credentials_client = CredentialsClientJSON(self.auth_provider,
                                                        **params)
        # Token clients do not use the catalog. They only need default_params.
        self.token_client = TokenClientJSON(CONF.identity.uri,
                                            **self.default_params)
        if CONF.identity_feature_enabled.api_v3:
            self.token_v3_client = V3TokenClientJSON(CONF.identity.uri_v3,
                                                     **self.default_params)


class AdminManager(Manager):

    """
    Manager object that uses the admin credentials for its
    managed client objects
    """

    def __init__(self, service=None):
        super(AdminManager, self).__init__(
            credentials=cred_provider.get_configured_credentials(
                'identity_admin'),
            service=service)
