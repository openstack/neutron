# Copyright 2026 Red Hat, Inc.
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


class FrrDriverError(Exception):
    """Base exception for FRR EVPN driver failures."""

    def __init__(self, message, step=None, cause=None):
        super().__init__(message)
        self.step = step
        self.cause = cause

    def __str__(self):
        return "%s - step: %s - cause: %s" % (
            super().__str__(), self.step, self.cause)


class FrrTemplateRenderError(FrrDriverError):
    """Template render/load error for FRR EVPN configuration."""


class FrrVrfError(FrrDriverError):
    """VRF operation error while preparing EVPN router state."""


class FrrDryrunError(FrrDriverError):
    """VTYSH dry-run validation error for FRR configuration."""


class FrrApplyError(FrrDriverError):
    """VTYSH apply error while configuring FRR."""
