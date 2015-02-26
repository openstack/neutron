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

from neutron.common import exceptions


class Invalid(exceptions.NeutronException):
    message = _("The value '%(value)s' for %(element)s is not valid.")


class CallbackFailure(Exception):

    def __init__(self, errors):
        self.errors = errors

    def __str__(self):
        return ','.join(str(error) for error in self.errors)


class NotificationError(object):

    def __init__(self, callback_id, error):
        self.callback_id = callback_id
        self.error = error

    def __str__(self):
        return 'Callback %s failed with "%s"' % (self.callback_id, self.error)
