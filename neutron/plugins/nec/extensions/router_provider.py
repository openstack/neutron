# Copyright 2013 NEC Corporation.  All rights reserved.
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

from neutron.api.v2 import attributes


LOG = logging.getLogger(__name__)

ROUTER_PROVIDER = 'provider'

ROUTER_PROVIDER_ATTRIBUTE = {
    'routers': {ROUTER_PROVIDER:
                {'allow_post': True,
                 'allow_put': False,
                 'is_visible': True,
                 'default': attributes.ATTR_NOT_SPECIFIED}
                }
}


class Router_provider(object):
    @classmethod
    def get_name(cls):
        return "Router Provider"

    @classmethod
    def get_alias(cls):
        return "router_provider"

    @classmethod
    def get_description(cls):
        return "Router Provider Support"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/router_provider/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-08-20T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return ROUTER_PROVIDER_ATTRIBUTE
        else:
            return {}
