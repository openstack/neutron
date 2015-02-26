# Copyright 2014 IBM Corp.
#
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

from neutron.i18n import _LI
from neutron.plugins.ibm.common import constants

LOG = logging.getLogger(__name__)

HTTP_OK = 200


class FakeClient(object):

    '''Fake Client for SDNVE controller.'''

    def __init__(self, **kwargs):
        LOG.info(_LI('Fake SDNVE controller initialized'))

    def sdnve_list(self, resource, **_params):
        LOG.info(_LI('Fake SDNVE controller: list'))
        return (HTTP_OK, None)

    def sdnve_show(self, resource, specific, **_params):
        LOG.info(_LI('Fake SDNVE controller: show'))
        return (HTTP_OK, None)

    def sdnve_create(self, resource, body):
        LOG.info(_LI('Fake SDNVE controller: create'))
        return (HTTP_OK, None)

    def sdnve_update(self, resource, specific, body=None):
        LOG.info(_LI('Fake SDNVE controller: update'))
        return (HTTP_OK, None)

    def sdnve_delete(self, resource, specific):
        LOG.info(_LI('Fake SDNVE controller: delete'))
        return (HTTP_OK, None)

    def sdnve_get_tenant_byid(self, id):
        LOG.info(_LI('Fake SDNVE controller: get tenant by id'))
        return id, constants.TENANT_TYPE_OF

    def sdnve_check_and_create_tenant(self, id, network_type=None):
        LOG.info(_LI('Fake SDNVE controller: check and create tenant'))
        return id

    def sdnve_get_controller(self):
        LOG.info(_LI('Fake SDNVE controller: get controller'))
        return None
