# Copyright (c) 2013 OpenStack Foundation
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
from abc import ABCMeta, abstractmethod

from neutron.common import exceptions as exc
from neutron.common import topics
from neutron.openstack.common import log

LOG = log.getLogger(__name__)

TUNNEL = 'tunnel'


class TunnelTypeDriver(object):
    """Define stable abstract interface for ML2 type drivers.

    tunnel type networks rely on tunnel endpoints. This class defines abstract
    methods to manage these endpoints.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def add_endpoint(self, ip):
        """Register the endpoint in the type_driver database.

        param ip: the ip of the endpoint
        """
        pass

    @abstractmethod
    def get_endpoints(self):
        """Get every endpoint managed by the type_driver

        :returns a list of dict [{id:endpoint_id, ip_address:endpoint_ip},..]
        """
        pass

    def _parse_tunnel_ranges(self, tunnel_ranges, current_range, tunnel_type):
        for entry in tunnel_ranges:
            entry = entry.strip()
            try:
                tun_min, tun_max = entry.split(':')
                tun_min = tun_min.strip()
                tun_max = tun_max.strip()
                current_range.append((int(tun_min), int(tun_max)))
            except ValueError as ex:
                LOG.error(_("Invalid tunnel ID range: '%(range)s' - %(e)s. "
                            "Agent terminated!"),
                          {'range': tunnel_ranges, 'e': ex})
        LOG.info(_("%(type)s ID ranges: %(range)s"),
                 {'type': tunnel_type, 'range': current_range})


class TunnelRpcCallbackMixin(object):

    def __init__(self, notifier, type_manager):
        self.notifier = notifier
        self.type_manager = type_manager

    def tunnel_sync(self, rpc_context, **kwargs):
        """Update new tunnel.

        Updates the database with the tunnel IP. All listening agents will also
        be notified about the new tunnel IP.
        """
        tunnel_ip = kwargs.get('tunnel_ip')
        tunnel_type = kwargs.get('tunnel_type')
        if not tunnel_type:
            msg = "network_type value needed by the ML2 plugin"
            raise exc.InvalidInput(error_message=msg)
        driver = self.type_manager.drivers.get(tunnel_type)
        if driver:
            tunnel = driver.obj.add_endpoint(tunnel_ip)
            tunnels = driver.obj.get_endpoints()
            entry = {'tunnels': tunnels}
            # Notify all other listening agents
            self.notifier.tunnel_update(rpc_context, tunnel.ip_address,
                                        tunnel_type)
            # Return the list of tunnels IP's to the agent
            return entry
        else:
            msg = _("network_type value '%s' not supported") % tunnel_type
            raise exc.InvalidInput(error_message=msg)


class TunnelAgentRpcApiMixin(object):

    def _get_tunnel_update_topic(self):
        return topics.get_topic_name(self.topic,
                                     TUNNEL,
                                     topics.UPDATE)

    def tunnel_update(self, context, tunnel_ip, tunnel_type):
        self.fanout_cast(context,
                         self.make_msg('tunnel_update',
                                       tunnel_ip=tunnel_ip,
                                       tunnel_type=tunnel_type),
                         topic=self._get_tunnel_update_topic())
