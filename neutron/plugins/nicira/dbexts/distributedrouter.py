# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Nicira Networks, Inc.  All rights reserved.
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
# @author: Salvatore Orlando, Nicira, Inc
#

from neutron.db import db_base_plugin_v2
from neutron.extensions import l3
from neutron.openstack.common import log as logging
from neutron.plugins.nicira.dbexts import nicira_models
from neutron.plugins.nicira.extensions import distributedrouter as dist_rtr

LOG = logging.getLogger(__name__)


class DistributedRouter_mixin(object):
    """Mixin class to enable distributed router support."""

    def _extend_router_dict_distributed(self, router_res, router_db):
        # Avoid setting attribute to None for routers already existing before
        # the data model was extended with the distributed attribute
        nsx_attrs = router_db['nsx_attributes']
        # Return False if nsx attributes are not definied for this
        # neutron router
        router_res[dist_rtr.DISTRIBUTED] = (
            nsx_attrs and nsx_attrs['distributed'] or False)

    def _process_distributed_router_create(
        self, context, router_db, router_req):
        """Ensures persistency for the 'distributed' attribute.

        Either creates or fetches the nicira extended attributes
        record for this router and stores the 'distributed'
        attribute value.
        This method should be called from within a transaction, as
        it does not start a new one.
        """
        if not router_db['nsx_attributes']:
            nsx_attributes = nicira_models.NSXRouterExtAttributes(
                router_id=router_db['id'],
                distributed=router_req['distributed'])
            context.session.add(nsx_attributes)
            router_db['nsx_attributes'] = nsx_attributes
        else:
            # The situation where the record already exists will
            # be likely once the NSXRouterExtAttributes model
            # will allow for defining several attributes pertaining
            # to different extensions
            router_db['nsx_attributes']['distributed'] = (
                router_req['distributed'])
        LOG.debug(_("Distributed router extension successfully processed "
                    "for router:%s"), router_db['id'])

    # Register dict extend functions for ports
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, [_extend_router_dict_distributed])
