"""
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
"""


def get_view_builder(req):
    """get view builder"""
    base_url = req.application_url
    return ViewBuilder(base_url)


class ViewBuilder(object):
    """
    ViewBuilder for Portprofile,
    derived from quantum.views.networks
    """
    def __init__(self, base_url):
        """
        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build(self, portprofile_data, is_detail=False):
        """Generic method used to generate a portprofile entity."""
        if is_detail:
            portprofile = self._build_detail(portprofile_data)
        else:
            portprofile = self._build_simple(portprofile_data)
        return portprofile

    def _build_simple(self, portprofile_data):
        """Return a simple description of a portprofile"""
        return dict(portprofile=dict(id=portprofile_data['profile_id']))

    def _build_detail(self, portprofile_data):
        """Return a detailed info of a portprofile."""
        if (portprofile_data['assignment'] is None):
            return dict(portprofile=dict(id=portprofile_data['profile_id'],
                                name=portprofile_data['profile_name'],
                                qos_name=portprofile_data['qos_name']))
        else:
            return dict(portprofile=dict(id=portprofile_data['profile_id'],
                                name=portprofile_data['profile_name'],
                                qos_name=portprofile_data['qos_name'],
                                assignment=portprofile_data['assignment']))
