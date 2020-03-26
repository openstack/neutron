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

from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from oslo_config import cfg
import sqlalchemy as sa
from sqlalchemy import sql

from neutron.conf.db import l3_gwmode_db
from neutron.db import l3_db
from neutron.db.models import l3 as l3_models


l3_gwmode_db.register_db_l3_gwmode_opts()


# Modify the Router Data Model adding the enable_snat attribute
setattr(l3_models.Router, 'enable_snat',
        sa.Column(sa.Boolean, default=True, server_default=sql.true(),
                  nullable=False))


@resource_extend.has_resource_extenders
class L3_NAT_dbonly_mixin(l3_db.L3_NAT_dbonly_mixin):
    """Mixin class to add configurable gateway modes."""

    @staticmethod
    @resource_extend.extends([l3_apidef.ROUTERS])
    def _extend_router_dict_gw_mode(router_res, router_db):
        if router_db.gw_port_id:
            nw_id = router_db.gw_port['network_id']
            router_res[l3_apidef.EXTERNAL_GW_INFO].update({
                'network_id': nw_id,
                'enable_snat': router_db.enable_snat,
                'external_fixed_ips': [
                    {'subnet_id': ip["subnet_id"],
                     'ip_address': ip["ip_address"]}
                    for ip in router_db.gw_port['fixed_ips']
                ]
            })

    def _update_router_gw_info(self, context, router_id, info, router=None):
        with db_api.CONTEXT_WRITER.using(context):
            # Always load the router inside the DB context.
            router = self._get_router(context, router_id)
            old_router = self._make_router_dict(router)
            router.enable_snat = self._get_enable_snat(info)
            router_body = {l3_apidef.ROUTER:
                           {l3_apidef.EXTERNAL_GW_INFO: info}}
            registry.publish(resources.ROUTER, events.PRECOMMIT_UPDATE, self,
                             payload=events.DBEventPayload(
                                 context, request_body=router_body,
                                 states=(old_router,), resource_id=router_id,
                                 desired_state=router))

        # Calls superclass, pass router db object for avoiding re-loading
        super(L3_NAT_dbonly_mixin, self)._update_router_gw_info(
            context, router_id, info, router=router)
        # Returning the router might come back useful if this
        # method is overridden in child classes
        return self._get_router(context, router_id)

    @staticmethod
    def _get_enable_snat(info):
        if info and 'enable_snat' in info:
            return info['enable_snat']
        # if enable_snat is not specified then use the default value
        return cfg.CONF.enable_snat_by_default

    def _build_routers_list(self, context, routers, gw_ports):
        routers = super(L3_NAT_dbonly_mixin, self)._build_routers_list(
            context, routers, gw_ports)
        for rtr in routers:
            gw_port_id = rtr['gw_port_id']
            # Collect gw ports only if available
            if gw_port_id and gw_ports.get(gw_port_id):
                rtr['gw_port'] = gw_ports[gw_port_id]
                # Add enable_snat key
                rtr['enable_snat'] = rtr[
                    l3_apidef.EXTERNAL_GW_INFO]['enable_snat']
        return routers


class L3_NAT_db_mixin(L3_NAT_dbonly_mixin, l3_db.L3_NAT_db_mixin):
    pass
