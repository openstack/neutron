# Copyright 2013 VMware, Inc.  All rights reserved.
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

from neutron.db import db_base_plugin_v2
from neutron.extensions import l3
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.dbexts import models

LOG = logging.getLogger(__name__)


class NsxRouterMixin(object):
    """Mixin class to enable nsx router support."""

    nsx_attributes = []

    def _extend_nsx_router_dict(self, router_res, router_db):
        nsx_attrs = router_db['nsx_attributes']
        # Return False if nsx attributes are not definied for this
        # neutron router
        for attr in self.nsx_attributes:
            name = attr['name']
            default = attr['default']
            router_res[name] = (
                nsx_attrs and nsx_attrs[name] or default)

    def _process_nsx_router_create(
        self, context, router_db, router_req):
        if not router_db['nsx_attributes']:
            kwargs = {}
            for attr in self.nsx_attributes:
                name = attr['name']
                default = attr['default']
                kwargs[name] = router_req.get(name, default)
            nsx_attributes = models.NSXRouterExtAttributes(
                router_id=router_db['id'], **kwargs)
            context.session.add(nsx_attributes)
            router_db['nsx_attributes'] = nsx_attributes
        else:
            # The situation where the record already exists will
            # be likely once the NSXRouterExtAttributes model
            # will allow for defining several attributes pertaining
            # to different extensions
            for attr in self.nsx_attributes:
                name = attr['name']
                default = attr['default']
                router_db['nsx_attributes'][name] = router_req.get(
                    name, default)
        LOG.debug(_("Nsx router extension successfully processed "
                    "for router:%s"), router_db['id'])

    # Register dict extend functions for ports
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_nsx_router_dict'])
