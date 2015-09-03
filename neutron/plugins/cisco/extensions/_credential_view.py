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
    """ViewBuilder for Credential, derived from neutron.views.networks."""

    def __init__(self, base_url):
        """Initialize builder.

        :param base_url: url of the root wsgi application
        """
        self.base_url = base_url

    def build(self, credential_data, is_detail=False):
        """Generic method used to generate a credential entity."""
        if is_detail:
            credential = self._build_detail(credential_data)
        else:
            credential = self._build_simple(credential_data)
        return credential

    def _build_simple(self, credential_data):
        """Return a simple description of credential."""
        return dict(credential=dict(id=credential_data['credential_id']))

    def _build_detail(self, credential_data):
        """Return a detailed description of credential."""
        return dict(credential=dict(id=credential_data['credential_id'],
                                    name=credential_data['user_name'],
                                    password=credential_data['password']))
