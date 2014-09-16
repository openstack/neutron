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

from eventlet import greenthread
from eventlet import queue
from heleosapi import exceptions as h_exc

from neutron.openstack.common import log as logging
from neutron.plugins.embrane.common import contexts as ctx
from neutron.services.loadbalancer.drivers.embrane.agent import lb_operations
from neutron.services.loadbalancer.drivers.embrane import constants as econ

LOG = logging.getLogger(__name__)


class Dispatcher(object):
    def __init__(self, driver, async=True):
        self._async = async
        self._driver = driver
        self.sync_items = dict()
        self.handlers = lb_operations.handlers

    def dispatch_lb(self, d_context, *args, **kwargs):
        item = d_context.item
        event = d_context.event
        n_context = d_context.n_context
        chain = d_context.chain

        item_id = item["id"]
        if event in self.handlers:
            for f in self.handlers[event]:
                first_run = False
                if item_id not in self.sync_items:
                    self.sync_items[item_id] = [queue.Queue()]
                    first_run = True
                self.sync_items[item_id][0].put(
                    ctx.OperationContext(event, n_context, item, chain, f,
                                         args, kwargs))
                if first_run:
                    t = greenthread.spawn(self._consume_lb,
                                          item_id,
                                          self.sync_items[item_id][0],
                                          self._driver,
                                          self._async)
                    self.sync_items[item_id].append(t)
                if not self._async:
                    t = self.sync_items[item_id][1]
                    t.wait()

    def _consume_lb(self, sync_item, sync_queue, driver, a_sync):
        current_state = None
        while True:
            try:
                if current_state == econ.DELETED:
                    del self.sync_items[sync_item]
                    return
                try:
                    operation_context = sync_queue.get(
                        block=a_sync,
                        timeout=econ.QUEUE_TIMEOUT)
                except queue.Empty:
                    del self.sync_items[sync_item]
                    return

                (operation_context.chain and
                 operation_context.chain.execute_all())

                transient_state = None
                try:
                    transient_state = operation_context.function(
                        driver, operation_context.n_context,
                        operation_context.item, *operation_context.args,
                        **operation_context.kwargs)
                except (h_exc.PendingDva, h_exc.DvaNotFound,
                        h_exc.BrokenInterface, h_exc.DvaCreationFailed,
                        h_exc.BrokenDva, h_exc.ConfigurationFailed) as ex:
                    LOG.warning(econ.error_map[type(ex)], ex.message)
                except h_exc.DvaDeleteFailed as ex:
                    LOG.warning(econ.error_map[type(ex)], ex.message)
                    transient_state = econ.DELETED
                finally:
                    # if the returned transient state is None, no operations
                    # are required on the DVA status
                    if transient_state == econ.DELETED:
                        current_state = driver._delete_vip(
                            operation_context.n_context,
                            operation_context.item)
                        # Error state cannot be reverted
                    else:
                        driver._update_vip_graph_state(
                            operation_context.n_context,
                            operation_context.item)
            except Exception:
                LOG.exception(_('Unhandled exception occurred'))
