# Copyright 2024 Red Hat, Inc.
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

from neutron_lib import rpc as n_rpc
from oslo_messaging import Target


class BasePluginApi(object):
    """Base agent side of the rpc API"""
    def __init__(self, topic, namespace, version):
        target = Target(
            topic=topic,
            namespace=namespace,
            version=version)
        self.client = n_rpc.get_client(target)

    def get_ports(self, context, port_filters):
        # NOTE(mtomaska): The MetadataRpcCallback (server side) API version 1.0
        # exposes get_ports, under the PLUGIN topic and None namespace.
        cctxt = self.client.prepare(version='1.0')
        return cctxt.call(context, 'get_ports', filters=port_filters)
