# Copyright 2013 Embrane, Inc.
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
from heleosapi import constants as h_con
from heleosapi import exceptions as h_exc
from oslo_log import log as logging

from neutron.i18n import _LE
from neutron.plugins.embrane.agent.operations import router_operations
from neutron.plugins.embrane.common import constants as p_con
from neutron.plugins.embrane.common import contexts as ctx

LOG = logging.getLogger(__name__)


class Dispatcher(object):

    def __init__(self, plugin, async=True):
        self._async = async
        self._plugin = plugin
        self.sync_items = dict()

    def dispatch_l3(self, d_context, args=(), kwargs={}):
        item = d_context.item
        event = d_context.event
        n_context = d_context.n_context
        chain = d_context.chain

        item_id = item["id"]
        handlers = router_operations.handlers
        if event in handlers:
            for f in handlers[event]:
                first_run = False
                if item_id not in self.sync_items:
                    self.sync_items[item_id] = (queue.Queue(),)
                    first_run = True
                self.sync_items[item_id][0].put(
                    ctx.OperationContext(event, n_context, item, chain, f,
                                         args, kwargs))
                t = None
                if first_run:
                    t = greenthread.spawn(self._consume_l3,
                                          item_id,
                                          self.sync_items[item_id][0],
                                          self._plugin,
                                          self._async)
                    self.sync_items[item_id] += (t,)
                if not self._async:
                    t = self.sync_items[item_id][1]
                    t.wait()

    def _consume_l3(self, sync_item, sync_queue, plugin, a_sync):
        current_state = None
        while True:
            try:
                # If the DVA is deleted, the thread (and the associated queue)
                # can die as well
                if current_state == p_con.Status.DELETED:
                    del self.sync_items[sync_item]
                    return
                try:
                    # If synchronous op, empty the queue as fast as possible
                    operation_context = sync_queue.get(
                        block=a_sync,
                        timeout=p_con.QUEUE_TIMEOUT)
                except queue.Empty:
                    del self.sync_items[sync_item]
                    return
                # Execute the preliminary operations
                (operation_context.chain and
                 operation_context.chain.execute_all())
                # Execute the main operation, a transient state is maintained
                # so that the consumer can decide if it has
                # to be burned to the DB
                transient_state = None
                try:
                    dva_state = operation_context.function(
                        plugin._esm_api,
                        operation_context.n_context.tenant_id,
                        operation_context.item,
                        *operation_context.args,
                        **operation_context.kwargs)
                    if dva_state == p_con.Status.DELETED:
                        transient_state = dva_state
                    else:
                        if not dva_state:
                            transient_state = p_con.Status.ERROR
                        elif dva_state == h_con.DvaState.POWER_ON:
                            transient_state = p_con.Status.ACTIVE
                        else:
                            transient_state = p_con.Status.READY

                except (h_exc.PendingDva, h_exc.DvaNotFound,
                        h_exc.BrokenInterface, h_exc.DvaCreationFailed,
                        h_exc.DvaCreationPending, h_exc.BrokenDva,
                        h_exc.ConfigurationFailed) as ex:
                    LOG.warning(p_con.error_map[type(ex)], ex.message)
                    transient_state = p_con.Status.ERROR
                except h_exc.DvaDeleteFailed as ex:
                    LOG.warning(p_con.error_map[type(ex)], ex.message)
                    transient_state = p_con.Status.DELETED
                finally:
                    # if the returned transient state is None, no operations
                    # are required on the DVA status
                    if transient_state:
                        if transient_state == p_con.Status.DELETED:
                            current_state = plugin._delete_router(
                                operation_context.n_context,
                                operation_context.item["id"])
                        # Error state cannot be reverted
                        elif transient_state != p_con.Status.ERROR:
                            current_state = plugin._update_neutron_state(
                                operation_context.n_context,
                                operation_context.item,
                                transient_state)
            except Exception:
                LOG.exception(_LE("Unhandled exception occurred"))
