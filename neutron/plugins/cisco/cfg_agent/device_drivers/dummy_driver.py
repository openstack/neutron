# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import logging

from oslo_serialization import jsonutils

from neutron.plugins.cisco.cfg_agent.device_drivers import devicedriver_api

LOG = logging.getLogger(__name__)


class DummyRoutingDriver(devicedriver_api.RoutingDriverBase):
    """Dummy Routing Driver.

    This class emulates a routing driver without a real backing device.
    """

    def __init__(self, **device_params):
        my_device_params = device_params
        # Datetime values causes json decoding errors. So removing it locally
        if my_device_params.get('created_at'):
            del my_device_params['created_at']
        LOG.debug(jsonutils.dumps(my_device_params, sort_keys=True, indent=4))

    ###### Public Functions ########
    def router_added(self, ri):
        LOG.debug("DummyDriver router_added() called.")

    def router_removed(self, ri):
        LOG.debug("DummyDriver router_removed() called.")

    def internal_network_added(self, ri, port):
        LOG.debug("DummyDriver internal_network_added() called.")
        LOG.debug("Int port data: " + jsonutils.dumps(port, sort_keys=True,
                  indent=4))

    def internal_network_removed(self, ri, port):
        LOG.debug("DummyDriver internal_network_removed() called.")

    def external_gateway_added(self, ri, ex_gw_port):
        LOG.debug("DummyDriver external_gateway_added() called.")
        LOG.debug("Ext port data: " + jsonutils.dumps(ex_gw_port,
                                                      sort_keys=True,
                                                      indent=4))

    def external_gateway_removed(self, ri, ex_gw_port):
        LOG.debug("DummyDriver external_gateway_removed() called.")

    def enable_internal_network_NAT(self, ri, port, ex_gw_port):
        LOG.debug("DummyDriver external_gateway_added() called.")

    def disable_internal_network_NAT(self, ri, port, ex_gw_port):
        LOG.debug("DummyDriver disable_internal_network_NAT() called.")

    def floating_ip_added(self, ri, ex_gw_port, floating_ip, fixed_ip):
        LOG.debug("DummyDriver floating_ip_added() called.")

    def floating_ip_removed(self, ri, ex_gw_port, floating_ip, fixed_ip):
        LOG.debug("DummyDriver floating_ip_removed() called.")

    def routes_updated(self, ri, action, route):
        LOG.debug("DummyDriver routes_updated() called.")

    def clear_connection(self):
        LOG.debug("DummyDriver clear_connection() called.")
