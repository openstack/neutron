# Copyright 2014 Cisco Systems, Inc.
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
#

"""
This file provides a wrapper to novaclient API, for getting the instacne's
information such as display_name.
"""

from keystoneclient.v2_0 import client as keyc

from neutron.openstack.common import log as logging
from novaclient import exceptions as nexc
from novaclient.v1_1 import client as nova_client


LOG = logging.getLogger(__name__)


class DFAInstanceAPI(object):
    """This class provides API to get information for a given instance."""

    def __init__(self, cfg):
        self._tenant_name = cfg.CONF.keystone_authtoken.admin_tenant_name
        self._user_name = cfg.CONF.keystone_authtoken.admin_user
        self._admin_password = cfg.CONF.keystone_authtoken.admin_password
        self._TIMEOUT_RESPONSE = 10
        self._token = None
        self._project_id = None
        self._auth_url = None
        self._token_id = None
        self._token = None
        self._novaclnt = None
        self._url = cfg.CONF.nova_admin_auth_url
        self._inst_info_cache = {}

    def _create_token(self):
        """Create new token for using novaclient API."""
        ks = keyc.Client(username=self._user_name,
                         password=self._admin_password,
                         tenant_name=self._tenant_name,
                         auth_url=self._url)
        result = ks.authenticate()
        if result:
            access = ks.auth_ref
            token = access.get('token')
            self._token_id = token['id']
            self._project_id = token['tenant'].get('id')
            service_catalog = access.get('serviceCatalog')
            for sc in service_catalog:
                if sc['type'] == "compute" and sc['name'] == 'nova':
                    endpoints = sc['endpoints']
                    for endp in endpoints:
                        self._auth_url = endp['adminURL']
            LOG.info(_('_create_token: token = %s'), token)

            # Create nova client.
            self._novaclnt = self._create_nova_client()

            return token

        else:
            # Failed request.
            LOG.error(_('Failed to send token create request.'))

    def _create_nova_client(self):
        """Creates nova client object."""
        try:
            clnt = nova_client.Client(self._user_name,
                                      self._token_id,
                                      self._project_id,
                                      self._auth_url,
                                      insecure=False,
                                      cacert=None)
            clnt.client.auth_token = self._token_id
            clnt.client.management_url = self._auth_url
            return clnt
        except nexc.Unauthorized:
            thismsg = (_('Failed to get novaclient:Unauthorised '
                      '%(proj)s %(user)s') % {'proj': self.project_id,
                                              'user': self._user_name})
            raise nexc.ClientException(thismsg)

        except nexc.AuthorizationFailure as err:
            raise nexc.ClientException(_("Failed to get novaclient %s") % err)

    def _get_instances_for_project(self, project_id):
        """Return all instances for a given project.

        :project_id: UUID of project (tenant)
        """
        search_opts = {'marker': None,
                       'all_tenants': True,
                       'project_id': project_id}
        self._create_token()
        try:
            servers = self._novaclnt.servers.list(True, search_opts)
            LOG.debug('_get_instances_for_project: servers=%s' % servers)
            return servers
        except nexc.Unauthorized:
            emsg = (_('Failed to get novaclient:Unauthorised '
                    'project_id=%(proj)s user=%(user)s'),
                    {'proj': self.project_id, 'name': self._user_name})
            LOG.exception(emsg)
            raise nexc.ClientException(emsg)
        except nexc.AuthorizationFailure as err:
            emsg = _("Failed to get novaclient %s")
            LOG.exception(emsg % err)
            raise nexc.ClientException(emsg % err)

    def get_instance_for_uuid(self, uuid, project_id):
        """Return instance name for given uuid of an instance and project.

        :uuid: Instance's UUID
        :project_id: UUID of project (tenant)
        """
        instance_name = None
        instance_name = self._inst_info_cache.get((uuid, project_id))
        if instance_name:
            return instance_name
        instances = self._get_instances_for_project(project_id)
        for inst in instances:
            if inst.id.replace('-', '') == uuid:
                LOG.debug('get_instance_for_uuid: name=%s' % inst.name)
                instance_name = inst.name
                self._inst_info_cache[(uuid, project_id)] = instance_name
                return instance_name
        return instance_name
