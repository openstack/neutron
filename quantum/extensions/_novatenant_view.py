# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
#
# @author: Ying Liu, Cisco Systems, Inc.
#

from quantum.plugins.cisco.common import cisco_constants as const


def get_view_builder(req):
    """get view builder """
    base_url = req.application_url
    return ViewBuilder(base_url)


class ViewBuilder(object):
    """
    ViewBuilder for novatenant,
    derived from quantum.views.networks
    """
    def __init__(self, base_url):
        """
        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build_host(self, host_data):
        """Return host description."""
        return dict(host_list=host_data[const.HOST_LIST])

    def build_vif(self, vif_data):
        """Return VIF description."""
        return dict(vif_desc=vif_data[const.VIF_DESC])

    def build_result(self, result_data):
        """Return result True/False"""
        return dict(result=result_data)
