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

from neutron_lib.api import faults
import oslo_i18n
from oslo_log import log as logging
from pecan import hooks

from neutron.api import api_common


LOG = logging.getLogger(__name__)


class ExceptionTranslationHook(hooks.PecanHook):
    def on_error(self, state, e):
        language = None
        if state.request.accept_language:
            language = state.request.accept_language.best_match(
                oslo_i18n.get_available_languages('neutron'))
        exc = api_common.convert_exception_to_http_exc(e, faults.FAULT_MAP,
                                                       language)
        if hasattr(exc, 'code') and 400 <= exc.code < 500:
            LOG.info('%(action)s failed (client error): %(exc)s',
                     {'action': state.request.method, 'exc': exc})
        else:
            LOG.exception('%s failed.', state.request.method)
        return exc
