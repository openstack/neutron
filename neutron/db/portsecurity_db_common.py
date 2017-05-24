# Copyright 2013 VMware, Inc.  All rights reserved.
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

from neutron_lib.api.definitions import port_security as psec

from neutron.db import _utils as db_utils
from neutron.objects import network
from neutron.objects.port.extensions import port_security as p_ps


class PortSecurityDbCommon(object):
    """Mixin class to add port security."""

    @staticmethod
    def _extend_port_security_dict(response_data, db_data):
        if db_data.get('port_security') is None:
            response_data[psec.PORTSECURITY] = psec.DEFAULT_PORT_SECURITY
        else:
            response_data[psec.PORTSECURITY] = (
                                db_data['port_security'][psec.PORTSECURITY])

    def _process_port_security_create(
        self, context, obj_cls, res_name, req, res):
        obj = obj_cls(
            context,
            id=res['id'],
            port_security_enabled=req[psec.PORTSECURITY]
        )
        obj.create()
        res[psec.PORTSECURITY] = req[psec.PORTSECURITY]
        return self._make_port_security_dict(obj, res_name)

    def _process_port_port_security_create(
        self, context, port_req, port_res):
        self._process_port_security_create(
            context, p_ps.PortSecurity, 'port',
            port_req, port_res)

    def _process_network_port_security_create(
        self, context, network_req, network_res):
        self._process_port_security_create(
            context, network.NetworkPortSecurity, 'network',
            network_req, network_res)

    def _get_security_binding(self, context, obj_cls, res_id):
        obj = obj_cls.get_object(context, id=res_id)
        # NOTE(ihrachys) the resource may have been created before port
        # security extension was enabled; return default value
        return obj.port_security_enabled if obj else psec.DEFAULT_PORT_SECURITY

    def _get_network_security_binding(self, context, network_id):
        return self._get_security_binding(
            context, network.NetworkPortSecurity, network_id)

    def _get_port_security_binding(self, context, port_id):
        return self._get_security_binding(context, p_ps.PortSecurity, port_id)

    def _process_port_port_security_update(
        self, context, port_req, port_res):
        self._process_port_security_update(
            context, p_ps.PortSecurity, 'port', port_req, port_res)

    def _process_network_port_security_update(
        self, context, network_req, network_res):
        self._process_port_security_update(
            context, network.NetworkPortSecurity, 'network',
            network_req, network_res)

    def _process_port_security_update(
        self, context, obj_cls, res_name, req, res):
        if psec.PORTSECURITY not in req:
            return
        port_security_enabled = req[psec.PORTSECURITY]

        obj = obj_cls.get_object(context, id=res['id'])
        if obj:
            obj.port_security_enabled = port_security_enabled
            obj.update()
            res[psec.PORTSECURITY] = port_security_enabled
        else:
            # NOTE(ihrachys) the resource may have been created before port
            # security extension was enabled; create the binding model
            self._process_port_security_create(
                context, obj_cls, res_name, req, res)

    @staticmethod
    def _make_port_security_dict(res, res_name, fields=None):
        res_ = {'%s_id' % res_name: res.id,
                psec.PORTSECURITY: res.port_security_enabled}
        return db_utils.resource_fields(res_, fields)
