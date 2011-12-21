"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Nicira Networks, Inc.  All rights reserved.
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
#
# @author: Brad Hall, Nicira Networks, Inc
#
"""


def get_view_builder(req):
    """get view builder"""
    base_url = req.application_url
    return ViewBuilder(base_url)


class ViewBuilder(object):
    """
    ViewBuilder for Port statistics.

    Port stats coming back from the plugin will look like this:
    {
      "rx_packets": 0,
      "rx_bytes": 0,
      "tx_errors": 0,
      "rx_errors": 0,
      "tx_bytes": 0,
      "tx_packets": 0
    }
    """
    def __init__(self, base_url):
        self.base_url = base_url

    def build(self, portstat_data, is_detail=True):
        # We just ignore is_detail -- it doesn't make sense in this context.
        return self._build(portstat_data)

    def _build(self, portstat_data):
        return portstat_data
