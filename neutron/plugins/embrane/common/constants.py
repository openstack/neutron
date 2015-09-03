# Copyright 2013 Embrane, Inc.
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

from heleosapi import exceptions as h_exc

from neutron.plugins.common import constants


# Router specific constants
UTIF_LIMIT = 7
QUEUE_TIMEOUT = 300


class Status(object):
    # Transient
    CREATING = constants.PENDING_CREATE
    UPDATING = constants.PENDING_UPDATE
    DELETING = constants.PENDING_DELETE
    # Final
    ACTIVE = constants.ACTIVE
    ERROR = constants.ERROR
    READY = constants.INACTIVE
    DELETED = "DELETED"  # not visible


class Events(object):
    CREATE_ROUTER = "create_router"
    UPDATE_ROUTER = "update_router"
    DELETE_ROUTER = "delete_router"
    GROW_ROUTER_IF = "grow_router_if"
    SHRINK_ROUTER_IF = "shrink_router_if"
    SET_NAT_RULE = "set_nat_rule"
    RESET_NAT_RULE = "reset_nat_rule"

_DVA_PENDING_ERROR_MSG = _("Dva is pending for the following reason: %s")
_DVA_NOT_FOUNT_ERROR_MSG = _("Dva can't be found to execute the operation, "
                             "probably was cancelled through the heleos UI")
_DVA_BROKEN_ERROR_MSG = _("Dva seems to be broken for reason %s")
_DVA_BROKEN_INTERFACE_ERROR_MSG = _("Dva interface seems to be broken "
                                    "for reason %s")
_DVA_CREATION_FAILED_ERROR_MSG = _("Dva creation failed reason %s")
_DVA_CREATION_PENDING_ERROR_MSG = _("Dva creation is in pending state "
                                    "for reason %s")
_CFG_FAILED_ERROR_MSG = _("Dva configuration failed for reason %s")
_DVA_DEL_FAILED_ERROR_MSG = _("Failed to delete the backend "
                              "router for reason %s. Please remove "
                              "it manually through the heleos UI")

error_map = {h_exc.PendingDva: _DVA_PENDING_ERROR_MSG,
             h_exc.DvaNotFound: _DVA_NOT_FOUNT_ERROR_MSG,
             h_exc.BrokenDva: _DVA_BROKEN_ERROR_MSG,
             h_exc.BrokenInterface: _DVA_BROKEN_INTERFACE_ERROR_MSG,
             h_exc.DvaCreationFailed: _DVA_CREATION_FAILED_ERROR_MSG,
             h_exc.DvaCreationPending: _DVA_CREATION_PENDING_ERROR_MSG,
             h_exc.ConfigurationFailed: _CFG_FAILED_ERROR_MSG,
             h_exc.DvaDeleteFailed: _DVA_DEL_FAILED_ERROR_MSG}
