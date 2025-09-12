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

import contextlib
import threading

from keystoneauth1 import exceptions as ks_exceptions
from keystoneauth1 import loading as ks_loading
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as exc
from neutron_lib.plugins import directory
from novaclient import api_versions
from novaclient import client as nova_client
from novaclient import exceptions as nova_exceptions
from oslo_config import cfg
from oslo_context import context as common_context
from oslo_log import log as logging
from oslo_utils import uuidutils
from sqlalchemy.orm import attributes as sql_attr
import tenacity

from neutron.notifiers import batch_notifier


LOG = logging.getLogger(__name__)

VIF_UNPLUGGED = 'network-vif-unplugged'
VIF_PLUGGED = 'network-vif-plugged'
VIF_DELETED = 'network-vif-deleted'
NEUTRON_NOVA_EVENT_STATUS_MAP = {constants.PORT_STATUS_ACTIVE: 'completed',
                                 constants.PORT_STATUS_ERROR: 'failed',
                                 constants.PORT_STATUS_DOWN: 'completed'}
NOVA_API_VERSION = "2.1"

NOTIFIER_ENABLE_DEFAULT = True
# NOTE(ralonsoh): the Nova notifier can be called simultaneously by several RPC
# callbacks from the agents (DHCP, L2), trying to update the provisioning
# status of a port. In order to handle each context notifier enable flag, a
# thread local variable is used.
_notifier_store = threading.local()


@registry.has_registry_receivers
class Notifier:

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        auth = ks_loading.load_auth_from_conf_options(cfg.CONF, 'nova')
        self.session = ks_loading.load_session_from_conf_options(
            cfg.CONF,
            'nova',
            auth=auth)
        self.extensions = [
            ext for ext in nova_client.discover_extensions(NOVA_API_VERSION)
            if ext.name == "server_external_events"]
        self.batch_notifier = batch_notifier.BatchNotifier(
            cfg.CONF.send_events_interval, self.send_events)

    @contextlib.contextmanager
    def context_enabled(self, enabled):
        try:
            _notifier_store.enable = enabled
            yield
        finally:
            _notifier_store.enable = NOTIFIER_ENABLE_DEFAULT

    def _get_nova_client(self):
        global_id = common_context.generate_request_id()
        return nova_client.Client(
            api_versions.APIVersion(NOVA_API_VERSION),
            session=self.session,
            region_name=cfg.CONF.nova.region_name,
            endpoint_type=cfg.CONF.nova.endpoint_type,
            extensions=self.extensions,
            connect_retries=cfg.CONF.http_retries,
            global_request_id=global_id)

    def _is_compute_port(self, port):
        try:
            if (port['device_id'] and
                    uuidutils.is_uuid_like(port['device_id']) and
                    port['device_owner'].startswith(
                        constants.DEVICE_OWNER_COMPUTE_PREFIX)):
                return True
        except (KeyError, AttributeError):
            pass
        return False

    def _get_network_changed_event(self, port):
        return {'name': 'network-changed',
                'server_uuid': port['device_id'],
                'tag': port['id']}

    def _get_port_delete_event(self, port):
        return {'server_uuid': port['device_id'],
                'name': VIF_DELETED,
                'tag': port['id']}

    @registry.receives(resources.PORT, [events.BEFORE_RESPONSE])
    @registry.receives(resources.FLOATING_IP, [events.BEFORE_RESPONSE])
    def _send_nova_notification(self, resource, event, trigger, payload=None):
        self.send_network_change(payload.action, payload.states[0],
                                 payload.latest_state)

    def send_network_change(self, action, original_obj,
                            returned_obj):
        """Called when a network change is made that nova cares about.

        :param action: the event that occurred.
        :param original_obj: the previous value of resource before action.
        :param returned_obj: the body returned to client as result of action.
        """

        if not cfg.CONF.notify_nova_on_port_data_changes:
            return

        # When neutron re-assigns floating ip from an original instance
        # port to a new instance port without disassociate it first, an
        # event should be sent for original instance, that will make nova
        # know original instance's info, and update database for it.
        if (action == 'update_floatingip' and
                returned_obj['floatingip'].get('port_id') and
                original_obj.get('port_id')):
            disassociate_returned_obj = {'floatingip': {'port_id': None}}
            event = self.create_port_changed_event(action, original_obj,
                                                   disassociate_returned_obj)
            self.batch_notifier.queue_event(event)

        event = self.create_port_changed_event(action, original_obj,
                                               returned_obj)
        self.batch_notifier.queue_event(event)

    def create_port_changed_event(self, action, original_obj, returned_obj):
        port = None
        if action in ['update_port', 'delete_port']:
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
            try:
                port = directory.get_plugin().get_port(ctx, port_id)
            except exc.PortNotFound:
                LOG.debug("Port %s was deleted, no need to send any "
                          "notification", port_id)
                return

        if port and self._is_compute_port(port):
            if action == 'delete_port':
                return self._get_port_delete_event(port)
            return self._get_network_changed_event(port)

    def _can_notify(self, port):
        if getattr(_notifier_store, 'enable', None) is None:
            _notifier_store.enable = NOTIFIER_ENABLE_DEFAULT

        if not _notifier_store.enable:
            LOG.debug("Nova notifier disabled")
            return False

        if not port.id:
            LOG.warning("Port ID not set! Nova will not be notified of "
                        "port status change.")
            return False

        # If there is no device_id set there is nothing we can do here.
        if not port.device_id:
            LOG.debug("device_id is not set on port %s yet.", port.id)
            return False

        # We only want to notify about nova ports.
        if not self._is_compute_port(port):
            return False

        return True

    def record_port_status_changed(self, port, current_port_status,
                                   previous_port_status, initiator):
        """Determine if nova needs to be notified due to port status change.
        """
        # clear out previous _notify_event
        port._notify_event = None
        if not self._can_notify(port):
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
                                       constants.PORT_STATUS_BUILD] and
              current_port_status in [constants.PORT_STATUS_ACTIVE,
                                      constants.PORT_STATUS_ERROR]):
            event_name = VIF_PLUGGED
        # All the remaining state transitions are of no interest to nova
        else:
            LOG.debug("Ignoring state change previous_port_status: "
                      "%(pre_status)s current_port_status: %(cur_status)s"
                      " port_id %(id)s",
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
        self.batch_notifier.queue_event(event)
        port._notify_event = None

    def notify_port_active_direct(self, port):
        """Notify nova about active port

        Used when port was wired on the host other than port's current host
        according to port binding. This happens during live migration.
        In this case ml2 plugin skips port status update but we still we need
        to notify nova.
        """
        if not self._can_notify(port):
            return

        port._notify_event = (
            {'server_uuid': port.device_id,
             'name': VIF_PLUGGED,
             'status': 'completed',
             'tag': port.id})
        self.send_port_status(None, None, port)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(
            ks_exceptions.RetriableConnectionFailure),
        wait=tenacity.wait_exponential(multiplier=0.01, max=1),
        stop=tenacity.stop_after_delay(1),
        after=tenacity.after_log(LOG, logging.DEBUG))
    def send_events(self, batched_events):
        LOG.debug("Sending events: %s", batched_events)
        novaclient = self._get_nova_client()
        try:
            response = novaclient.server_external_events.create(
                batched_events)
        except ks_exceptions.EndpointNotFound:
            LOG.exception("Nova endpoint not found, invalidating the session")
            self.session.invalidate()
        except nova_exceptions.NotFound:
            LOG.debug("Nova returned NotFound for event: %s",
                      batched_events)
        except ks_exceptions.RetriableConnectionFailure:
            raise
            # next clause handles all exceptions
            # so reraise for retry decorator
        except Exception:
            LOG.exception("Failed to notify nova on events: %s",
                          batched_events)
        else:
            if not isinstance(response, list):
                LOG.error("Error response returned from nova: %s",
                          response)
                return
            response_error = False
            for event in response:
                try:
                    code = event['code']
                except KeyError:
                    response_error = True
                    continue
                if hasattr(response, 'request_ids'):
                    msg = f"Nova event matching {response.request_ids}"
                else:
                    msg = "Nova event"
                if code != 200:
                    LOG.warning("%s: %s returned with failed "
                                "status", msg, event)
                else:
                    LOG.info("%s response: %s", msg, event)
            if response_error:
                LOG.error("Error response returned from nova: %s",
                          response)
