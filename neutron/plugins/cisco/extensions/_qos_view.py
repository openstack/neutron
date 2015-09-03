# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
    """ViewBuilder for QoS, derived from neutron.views.networks."""

    def __init__(self, base_url):
        """Initialize builder.

        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build(self, qos_data, is_detail=False):
        """Generic method used to generate a QoS entity."""
        if is_detail:
            qos = self._build_detail(qos_data)
        else:
            qos = self._build_simple(qos_data)
        return qos

    def _build_simple(self, qos_data):
        """Return a simple description of qos."""
        return dict(qos=dict(id=qos_data['qos_id']))

    def _build_detail(self, qos_data):
        """Return a detailed description of qos."""
        return dict(qos=dict(id=qos_data['qos_id'],
                             name=qos_data['qos_name'],
                             description=qos_data['qos_desc']))
