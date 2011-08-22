"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Ying Liu, Cisco Systems, Inc.
#
"""
import logging


# pylint: disable-msg=E0602
class ExtensionException(Exception):
    """Quantum Cisco api Exception
    
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
        """Error Msg"""
        return self._error_string


class ProcessExecutionError(IOError):
    """Process Exe Error"""
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
    """Error Class"""
    def __init__(self, message=None):
        super(Error, self).__init__(message)


class ApiError(Error):
    """Api Error"""
    def __init__(self, message='Unknown', code='Unknown'):
        self.message = message
        self.code = code
        super(ApiError, self).__init__('%s: %s' % (code, message))


class NotFound(ExtensionException):
    """Error Msg"""
    pass


class ClassNotFound(NotFound):
    """Extension Error Msg"""
    message = _("Class %(class_name)s could not be found")


class PortprofileNotFound(NotFound):
    """Extension Error Msg"""
    message = _("Portprofile %(_id)s could not be found")
    
    
class NovatenantNotFound(NotFound):
    """Extension Error Msg"""
    message = _("Novatenant %(_id)s could not be found")


class PortNotFound(NotFound):
    """Extension Error"""
    message = _("Port %(port_id)s could not be found " \
                "on Network %(net_id)s")
    
    
class CredentialNotFound(NotFound):
    """Extension Error"""
    message = _("Credential %(_id)s could not be found")
    
    
class QosNotFound(NotFound):
    """Extension Error"""
    message = _("QoS %(_id)s could not be found")
    

class Duplicate(Error):
    """Duplication Error"""
    pass


class NotAuthorized(Error):
    "Not Auth Error"
    pass


class NotEmpty(Error):
    """Not Empty Error"""
    pass


class Invalid(Error):
    """Invalid Error"""
    pass


class InvalidContentType(Invalid):
    message = _("Invalid content type %(content_type)s.")


class BadInputError(Exception):
    """Error resulting from a client sending bad input to a server"""
    pass


class MissingArgumentError(Error):
    """Miss arg error"""
    pass


def wrap_exception(afunc):
    """Wrap Exception"""
    def _wrap(*args, **kw):
        """Internal Wrap Exception func"""
        try:
            return afunc(*args, **kw)
        except Exception, exp:
            if not isinstance(exp, Error):
                #exc_type, exc_value, exc_traceback = sys.exc_info()
                logging.exception('Uncaught exception')
                #logging.error(traceback.extract_stack(exc_traceback))
                raise Error(str(exp))
            raise
    _wrap.func_name = afunc.func_name
    return _wrap
