# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack LLC.
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

from quantum import context
from quantum.openstack.common import log as logging
from quantum.openstack.common.rpc import dispatcher


LOG = logging.getLogger(__name__)


class PluginRpcDispatcher(dispatcher.RpcDispatcher):
    """This class is used to convert RPC common context into
    Quantum Context."""

    def __init__(self, callbacks):
        super(PluginRpcDispatcher, self).__init__(callbacks)

    def dispatch(self, rpc_ctxt, version, method, **kwargs):
        rpc_ctxt_dict = rpc_ctxt.to_dict()
        user_id = rpc_ctxt_dict.pop('user_id', None)
        if not user_id:
            user_id = rpc_ctxt_dict.pop('user', None)
        tenant_id = rpc_ctxt_dict.pop('tenant_id', None)
        if not tenant_id:
            tenant_id = rpc_ctxt_dict.pop('project_id', None)
        quantum_ctxt = context.Context(user_id, tenant_id, **rpc_ctxt_dict)
        return super(PluginRpcDispatcher, self).dispatch(
            quantum_ctxt, version, method, **kwargs)
