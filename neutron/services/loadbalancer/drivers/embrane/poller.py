# Copyright 2014 Embrane, Inc.
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

from heleosapi import exceptions as h_exc

from neutron import context
from neutron.db.loadbalancer import loadbalancer_db as ldb
from neutron.db import servicetype_db as sdb
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.common import constants as ccon
from neutron.plugins.embrane.common import contexts as embrane_ctx
from neutron.services.loadbalancer.drivers.embrane import constants as econ

LOG = logging.getLogger(__name__)
skip_states = [ccon.PENDING_CREATE,
               ccon.PENDING_DELETE,
               ccon.PENDING_UPDATE,
               ccon.ERROR]


class Poller(object):
    def __init__(self, driver):
        self.dispatcher = driver._dispatcher
        service_type_manager = sdb.ServiceTypeManager.get_instance()
        self.provider = (service_type_manager.get_service_providers(
            None, filters={
                'service_type': [ccon.LOADBALANCER],
                'driver': ['neutron.services.loadbalancer.drivers.'
                           'embrane.driver.EmbraneLbaas']}))[0]['name']

    def start_polling(self, interval):
        loop_call = loopingcall.FixedIntervalLoopingCall(self._run)
        loop_call.start(interval=interval)
        return loop_call

    def _run(self):
        ctx = context.get_admin_context()
        try:
            self.synchronize_vips(ctx)
        except h_exc.PollingException as e:
            LOG.exception(_('Unhandled exception occurred'), e)

    def synchronize_vips(self, ctx):
        session = ctx.session
        vips = session.query(ldb.Vip).join(
            sdb.ProviderResourceAssociation,
            sdb.ProviderResourceAssociation.resource_id ==
            ldb.Vip.pool_id).filter(
                sdb.ProviderResourceAssociation.provider_name == self.provider)
        # No need to check pending states
        for vip in vips:
            if vip['status'] not in skip_states:
                self.dispatcher.dispatch_lb(
                    d_context=embrane_ctx.DispatcherContext(
                        econ.Events.POLL_GRAPH, vip, ctx, None),
                    args=())
