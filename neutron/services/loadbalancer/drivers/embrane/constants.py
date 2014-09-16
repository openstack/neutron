# Copyright 2014 Embrane, Inc.
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

from heleosapi import constants as h_con
from heleosapi import exceptions as h_exc

from neutron.plugins.common import constants as ccon

DELETED = 'DELETED'  # not visible status
QUEUE_TIMEOUT = 300
BACK_SUB_LIMIT = 6


class BackendActions:
    UPDATE = 'update'
    GROW = 'grow'
    REMOVE = 'remove'
    SHRINK = 'shrink'


class Events:
    CREATE_VIP = 'create_vip'
    UPDATE_VIP = 'update_vip'
    DELETE_VIP = 'delete_vip'
    UPDATE_POOL = 'update_pool'
    UPDATE_MEMBER = 'update_member'
    ADD_OR_UPDATE_MEMBER = 'add_or_update_member'
    REMOVE_MEMBER = 'remove_member'
    DELETE_MEMBER = 'delete_member'
    POLL_GRAPH = 'poll_graph'
    ADD_POOL_HM = "create_pool_hm"
    UPDATE_POOL_HM = "update_pool_hm"
    DELETE_POOL_HM = "delete_pool_hm"


_DVA_PENDING_ERROR_MSG = _('Dva is pending for the following reason: %s')
_DVA_NOT_FOUNT_ERROR_MSG = _('%s, '
                             'probably was cancelled through the heleos UI')
_DVA_BROKEN_ERROR_MSG = _('Dva seems to be broken for reason %s')
_DVA_CREATION_FAILED_ERROR_MSG = _('Dva creation failed reason %s')
_DVA_CREATION_PENDING_ERROR_MSG = _('Dva creation is in pending state '
                                    'for reason %s')
_CFG_FAILED_ERROR_MSG = _('Dva configuration failed for reason %s')
_DVA_DEL_FAILED_ERROR_MSG = _('Failed to delete the backend '
                              'load balancer for reason %s. Please remove '
                              'it manually through the heleos UI')
NO_MEMBER_SUBNET_WARN = _('No subnet is associated to member %s (required '
                          'to identify the proper load balancer port)')

error_map = {h_exc.PendingDva: _DVA_PENDING_ERROR_MSG,
             h_exc.DvaNotFound: _DVA_NOT_FOUNT_ERROR_MSG,
             h_exc.BrokenDva: _DVA_BROKEN_ERROR_MSG,
             h_exc.DvaCreationFailed: _DVA_CREATION_FAILED_ERROR_MSG,
             h_exc.DvaCreationPending: _DVA_CREATION_PENDING_ERROR_MSG,
             h_exc.ConfigurationFailed: _CFG_FAILED_ERROR_MSG,
             h_exc.DvaDeleteFailed: _DVA_DEL_FAILED_ERROR_MSG}

state_map = {h_con.DvaState.POWER_ON: ccon.ACTIVE,
             None: ccon.ERROR,
             DELETED: DELETED}
