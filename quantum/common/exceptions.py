# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira Networks, Inc
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

"""
Quantum base exception handling, including decorator for re-raising
Quantum-type exceptions. SHOULD include dedicated exception logging.
"""

import logging
import gettext

gettext.install('quantum', unicode=1)


class QuantumException(Exception):
    """Base Quantum Exception

    Taken from nova.exception.NovaException
    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.

    """
    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            self._error_string = self.message % kwargs

        except Exception:
            # at least get the core message out if something happened
            self._error_string = self.message

    def __str__(self):
        return self._error_string


class ProcessExecutionError(IOError):
    def __init__(self, stdout=None, stderr=None, exit_code=None, cmd=None,
                 description=None):
        if description is None:
            description = "Unexpected error while running command."
        if exit_code is None:
            exit_code = '-'
        message = "%s\nCommand: %s\nExit code: %s\nStdout: %r\nStderr: %r" % (
                  description, cmd, exit_code, stdout, stderr)
        IOError.__init__(self, message)


class Error(Exception):
    def __init__(self, message=None):
        super(Error, self).__init__(message)


class ApiError(Error):
    def __init__(self, message='Unknown', code='Unknown'):
        self.message = message
        self.code = code
        super(ApiError, self).__init__('%s: %s' % (code, message))


class NotFound(QuantumException):
    pass


class ClassNotFound(NotFound):
    message = _("Class %(class_name)s could not be found")


class NetworkNotFound(NotFound):
    message = _("Network %(net_id)s could not be found")


class PortNotFound(NotFound):
    message = _("Port %(port_id)s could not be found " \
                "on network %(net_id)s")


class StateInvalid(QuantumException):
    message = _("Unsupported port state: %(port_state)s")


class NetworkInUse(QuantumException):
    message = _("Unable to complete operation on network %(net_id)s. " \
                "There is one or more attachments plugged into its ports.")


class PortInUse(QuantumException):
    message = _("Unable to complete operation on port %(port_id)s " \
                "for network %(net_id)s. The attachment '%(att_id)s" \
                "is plugged into the logical port.")


class AlreadyAttached(QuantumException):
    message = _("Unable to plug the attachment %(att_id)s into port " \
                "%(port_id)s for network %(net_id)s. The attachment is " \
                "already plugged into port %(att_port_id)s")


# NOTE: on the client side, we often do not know all of the information
# that is known on the server, thus, we create separate exception for
# those scenarios
class PortInUseClient(QuantumException):
    message = _("Unable to complete operation on port %(port_id)s " \
                "for network %(net_id)s. An attachment " \
                "is plugged into the logical port.")


class AlreadyAttachedClient(QuantumException):
    message = _("Unable to plug the attachment %(att_id)s into port " \
                "%(port_id)s for network %(net_id)s. The attachment is " \
                "already plugged into another port.")


class MalformedRequestBody(QuantumException):
    message = _("Malformed request body: %(reason)s")


class Duplicate(Error):
    pass


class NotAuthorized(Error):
    pass


class NotEmpty(Error):
    pass


class Invalid(Error):
    pass


class InvalidContentType(Invalid):
    message = _("Invalid content type %(content_type)s.")


class BadInputError(Exception):
    """Error resulting from a client sending bad input to a server"""
    pass


class MissingArgumentError(Error):
    pass


class NotImplementedError(Error):
    pass


def wrap_exception(f):
    def _wrap(*args, **kw):
        try:
            return f(*args, **kw)
        except Exception, e:
            if not isinstance(e, Error):
                #exc_type, exc_value, exc_traceback = sys.exc_info()
                logging.exception('Uncaught exception')
                #logging.error(traceback.extract_stack(exc_traceback))
                raise Error(str(e))
            raise
    _wrap.func_name = f.func_name
    return _wrap
