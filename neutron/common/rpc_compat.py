# Copyright (c) 2014 Red Hat, Inc.
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

from neutron.openstack.common.rpc import common as rpc_common
from neutron.openstack.common.rpc import proxy


class RpcProxy(proxy.RpcProxy):
    '''
    This class is created to facilitate migration from oslo-incubator
    RPC layer implementation to oslo.messaging and is intended to
    emulate RpcProxy class behaviour using oslo.messaging API once the
    migration is applied.
    '''


# exceptions
RPCException = rpc_common.RPCException
RemoteError = rpc_common.RemoteError
MessagingTimeout = rpc_common.Timeout
