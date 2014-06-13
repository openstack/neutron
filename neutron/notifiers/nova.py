# Copyright (c) 2014 OpenStack Foundation.
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

import eventlet
import novaclient.v1_1.client as nclient
from novaclient.v1_1.contrib import server_external_events
from oslo.config import cfg
from sqlalchemy.orm import attributes as sql_attr

from neutron.common import constants
from neutron import context
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils


LOG = logging.getLogger(__name__)

VIF_UNPLUGGED = 'network-vif-unplugged'
VIF_PLUGGED = 'network-vif-plugged'
NEUTRON_NOVA_EVENT_STATUS_MAP = {constants.PORT_STATUS_ACTIVE: 'completed',
                                 constants.PORT_STATUS_ERROR: 'failed',
                                 constants.PORT_STATUS_DOWN: 'completed'}


class Notifier(object):

    def __init__(self):
        # TODO(arosen): we need to cache the endpoints and figure out
        # how to deal with different regions here....
        bypass_url = "%s/%s" % (cfg.CONF.nova_url,
                                cfg.CONF.nova_admin_tenant_id)
        self.nclient = nclient.Client(
            username=cfg.CONF.nova_admin_username,
            api_key=cfg.CONF.nova_admin_password,
            project_id=None,
            tenant_id=cfg.CONF.nova_admin_tenant_id,
            auth_url=cfg.CONF.nova_admin_auth_url,
            bypass_url=bypass_url,
            region_name=cfg.CONF.nova_region_name,
            extensions=[server_external_events])
        self.pending_events = []
        self._waiting_to_send = False

    def queue_event(self, event):
        """Called to queue sending an event with the next batch of events.

        Sending events individually, as they occur, has been problematic as it
        can result in a flood of sends.  Previously, there was a loopingcall
        thread that would send batched events on a periodic interval.  However,
        maintaining a persistent thread in the loopingcall was also
        problematic.

        This replaces the loopingcall with a mechanism that creates a
        short-lived thread on demand when the first event is queued.  That
        thread will sleep once for the same send_events_interval to allow other
        events to queue up in pending_events and then will send them when it
        wakes.

        If a thread is already alive and waiting, this call will simply queue
        the event and return leaving it up to the thread to send it.

        :param event: the event that occured.
        """
        if not event:
            return

        self.pending_events.append(event)

        if self._waiting_to_send:
            return

        self._waiting_to_send = True

        def last_out_sends():
            eventlet.sleep(cfg.CONF.send_events_interval)
            self._waiting_to_send = False
            self.send_events()

        eventlet.spawn_n(last_out_sends)

    def _is_compute_port(self, port):
        try:
            if (port['device_id'] and uuidutils.is_uuid_like(port['device_id'])
                    and port['device_owner'].startswith('compute:')):
                return True
        except (KeyError, AttributeError):
            pass
        return False

    def _get_network_changed_event(self, device_id):
        return {'name': 'network-changed',
                'server_uuid': device_id}

    @property
    def _plugin(self):
        # NOTE(arosen): this cannot be set in __init__ currently since
        # this class is initalized at the same time as NeutronManager()
        # which is decorated with synchronized()
        if not hasattr(self, '_plugin_ref'):
            self._plugin_ref = manager.NeutronManager.get_plugin()
        return self._plugin_ref

    def send_network_change(self, action, original_obj,
                            returned_obj):
        """Called when a network change is made that nova cares about.

        :param action: the event that occured.
        :param original_obj: the previous value of resource before action.
        :param returned_obj: the body returned to client as result of action.
        """

        if not cfg.CONF.notify_nova_on_port_data_changes:
            return

        event = self.create_port_changed_event(action, original_obj,
                                               returned_obj)
        self.queue_event(event)

    def create_port_changed_event(self, action, original_obj, returned_obj):
        port = None
        if action == 'update_port':
            port = returned_obj['port']

        elif action in ['update_floatingip', 'create_floatingip',
                        'delete_floatingip']:
            # NOTE(arosen) if we are associating a floatingip the
            # port_id is in the returned_obj. Otherwise on disassociate
            # it's in the original_object
            port_id = (returned_obj['floatingip'].get('port_id') or
                       original_obj.get('port_id'))

            if port_id is None:
                return

            ctx = context.get_admin_context()
            port = self._plugin.get_port(ctx, port_id)

        if port and self._is_compute_port(port):
            return self._get_network_changed_event(port['device_id'])

    def record_port_status_changed(self, port, current_port_status,
                                   previous_port_status, initiator):
        """Determine if nova needs to be notified due to port status change.
        """
        # clear out previous _notify_event
        port._notify_event = None
        # If there is no device_id set there is nothing we can do here.
        if not port.device_id:
            LOG.debug(_("device_id is not set on port yet."))
            return

        if not port.id:
            LOG.warning(_("Port ID not set! Nova will not be notified of "
                          "port status change."))
            return

        # We only want to notify about nova ports.
        if not self._is_compute_port(port):
            return

        # We notify nova when a vif is unplugged which only occurs when
        # the status goes from ACTIVE to DOWN.
        if (previous_port_status == constants.PORT_STATUS_ACTIVE and
                current_port_status == constants.PORT_STATUS_DOWN):
            event_name = VIF_UNPLUGGED

        # We only notify nova when a vif is plugged which only occurs
        # when the status goes from:
        # NO_VALUE/DOWN/BUILD -> ACTIVE/ERROR.
        elif (previous_port_status in [sql_attr.NO_VALUE,
                                       constants.PORT_STATUS_DOWN,
                                       constants.PORT_STATUS_BUILD]
              and current_port_status in [constants.PORT_STATUS_ACTIVE,
                                          constants.PORT_STATUS_ERROR]):
            event_name = VIF_PLUGGED
        # All the remaining state transitions are of no interest to nova
        else:
            LOG.debug(_("Ignoring state change previous_port_status: "
                        "%(pre_status)s current_port_status: %(cur_status)s"
                        " port_id %(id)s") %
                      {'pre_status': previous_port_status,
                       'cur_status': current_port_status,
                       'id': port.id})
            return

        port._notify_event = (
            {'server_uuid': port.device_id,
             'name': event_name,
             'status': NEUTRON_NOVA_EVENT_STATUS_MAP.get(current_port_status),
             'tag': port.id})

    def send_port_status(self, mapper, connection, port):
        event = getattr(port, "_notify_event", None)
        self.queue_event(event)
        port._notify_event = None

    def send_events(self):
        batched_events = []
        for event in range(len(self.pending_events)):
            batched_events.append(self.pending_events.pop())

        if not batched_events:
            return

        LOG.debug(_("Sending events: %s"), batched_events)
        try:
            response = self.nclient.server_external_events.create(
                batched_events)
        except Exception:
            LOG.exception(_("Failed to notify nova on events: %s"),
                          batched_events)
        else:
            if not isinstance(response, list):
                LOG.error(_("Error response returned from nova: %s"),
                          response)
                return
            response_error = False
            for event in response:
                try:
                    code = event['code']
                except KeyError:
                    response_error = True
                    continue
                if code != 200:
                    LOG.warning(_("Nova event: %s returned with failed "
                                  "status"), event)
                else:
                    LOG.info(_("Nova event response: %s"), event)
            if response_error:
                LOG.error(_("Error response returned from nova: %s"),
                          response)
