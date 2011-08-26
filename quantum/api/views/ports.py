# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Citrix Systems
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


def get_view_builder(req):
    base_url = req.application_url
    return ViewBuilder(base_url)


class ViewBuilder(object):

    def __init__(self, base_url=None):
        """
        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build(self, port_data, port_details=False, att_details=False):
        """Generic method used to generate a port entity."""
        port = dict(port=dict(id=port_data['port-id']))
        if port_details:
            port['port']['state'] = port_data['port-state']
        if att_details and port_data['attachment']:
            port['port']['attachment'] = dict(id=port_data['attachment'])
        return port
