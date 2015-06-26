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

from keystoneclient import auth as ks_auth
from keystoneclient.auth.identity import v2 as v2_auth
from keystoneclient import session as ks_session
from novaclient import client as nova_client
from novaclient import exceptions as nova_exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
from oslo_utils import uuidutils
from sqlalchemy.orm import attributes as sql_attr

from neutron.common import constants
from neutron import context
from neutron.i18n import _LE, _LI, _LW
from neutron import manager
from neutron.notifiers import batch_notifier


LOG = logging.getLogger(__name__)

VIF_UNPLUGGED = 'network-vif-unplugged'
VIF_PLUGGED = 'network-vif-plugged'
NEUTRON_NOVA_EVENT_STATUS_MAP = {constants.PORT_STATUS_ACTIVE: 'completed',
                                 constants.PORT_STATUS_ERROR: 'failed',
                                 constants.PORT_STATUS_DOWN: 'completed'}
NOVA_API_VERSION = "2"


class DefaultAuthPlugin(v2_auth.Password):
    """A wrapper around standard v2 user/pass to handle bypass url.

    This is only necessary because novaclient doesn't support endpoint_override
    yet - bug #1403329.

    When this bug is fixed we can pass the endpoint_override to the client
    instead and remove this class.
    """

    def __init__(self, **kwargs):
        self._endpoint_override = kwargs.pop('endpoint_override', None)
        super(DefaultAuthPlugin, self).__init__(**kwargs)

    def get_endpoint(self, session, **kwargs):
        if self._endpoint_override:
            return self._endpoint_override

        return super(DefaultAuthPlugin, self).get_endpoint(session, **kwargs)


class Notifier(object):

    def __init__(self):
        # FIXME(jamielennox): A notifier is being created for each Controller
        # and each Notifier is handling it's own auth. That means that we are
        # authenticating the exact same thing len(controllers) times. This
        # should be an easy thing to optimize.
        auth = ks_auth.load_from_conf_options(cfg.CONF, 'nova')
        endpoint_override = None

        if not auth:
            LOG.warning(_LW('Authenticating to nova using nova_admin_* options'
                            ' is deprecated. This should be done using'
                            ' an auth plugin, like password'))

            if cfg.CONF.nova_admin_tenant_id:
                endpoint_override = "%s/%s" % (cfg.CONF.nova_url,
                                               cfg.CONF.nova_admin_tenant_id)

            auth = DefaultAuthPlugin(
                auth_url=cfg.CONF.nova_admin_auth_url,
                username=cfg.CONF.nova_admin_username,
                password=cfg.CONF.nova_admin_password,
                tenant_id=cfg.CONF.nova_admin_tenant_id,
                tenant_name=cfg.CONF.nova_admin_tenant_name,
                endpoint_override=endpoint_override)

        session = ks_session.Session.load_from_conf_options(cfg.CONF,
                                                            'nova',
                                                            auth=auth)

        # NOTE(andreykurilin): novaclient.v1_1 was renamed to v2 and there is
        # no way to import the contrib module directly without referencing v2,
        # which would only work for novaclient >= 2.21.0.
        novaclient_cls = nova_client.get_client_class(NOVA_API_VERSION)
        server_external_events = importutils.import_module(
            novaclient_cls.__module__.replace(
                ".client", ".contrib.server_external_events"))

        self.nclient = novaclient_cls(
            session=session,
            region_name=cfg.CONF.nova.region_name,
            extensions=[server_external_events])
        self.batch_notifier = batch_notifier.BatchNotifier(
            cfg.CONF.send_events_interval, self.send_events)

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
        # this class is initialized at the same time as NeutronManager()
        # which is decorated with synchronized()
        if not hasattr(self, '_plugin_ref'):
            self._plugin_ref = manager.NeutronManager.get_plugin()
        return self._plugin_ref

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
        if (action == 'update_floatingip'
                and returned_obj['floatingip'].get('port_id')
                and original_obj.get('port_id')):
            disassociate_returned_obj = {'floatingip': {'port_id': None}}
            event = self.create_port_changed_event(action, original_obj,
                                                   disassociate_returned_obj)
            self.batch_notifier.queue_event(event)

        event = self.create_port_changed_event(action, original_obj,
                                               returned_obj)
        self.batch_notifier.queue_event(event)

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
            LOG.debug("device_id is not set on port yet.")
            return

        if not port.id:
            LOG.warning(_LW("Port ID not set! Nova will not be notified of "
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

    def send_events(self, batched_events):
        LOG.debug("Sending events: %s", batched_events)
        try:
            response = self.nclient.server_external_events.create(
                batched_events)
        except nova_exceptions.NotFound:
            LOG.warning(_LW("Nova returned NotFound for event: %s"),
                        batched_events)
        except Exception:
            LOG.exception(_LE("Failed to notify nova on events: %s"),
                          batched_events)
        else:
            if not isinstance(response, list):
                LOG.error(_LE("Error response returned from nova: %s"),
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
                    LOG.warning(_LW("Nova event: %s returned with failed "
                                    "status"), event)
                else:
                    LOG.info(_LI("Nova event response: %s"), event)
            if response_error:
                LOG.error(_LE("Error response returned from nova: %s"),
                          response)
