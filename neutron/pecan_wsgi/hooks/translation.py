# Copyright (c) 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging
from pecan import hooks
import webob.exc

from neutron._i18n import _
from neutron.api.v2 import base as v2base
from neutron.i18n import _LE


LOG = logging.getLogger(__name__)


class ExceptionTranslationHook(hooks.PecanHook):
    def on_error(self, state, e):
        # if it's already an http error, just return to let it go through
        if isinstance(e, webob.exc.WSGIHTTPException):
            return
        for exc_class, to_class in v2base.FAULT_MAP.items():
            if isinstance(e, exc_class):
                raise to_class(getattr(e, 'msg', e.message))
        # leaked unexpected exception, convert to boring old 500 error and
        # hide message from user in case it contained sensitive details
        LOG.exception(_LE("An unexpected exception was caught: %s"), e)
        raise webob.exc.HTTPInternalServerError(
            _("An unexpected internal error occurred."))
