# Copyright (c) 2015 Rackspace
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

import re
import six

from oslo_config import cfg

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as n_exc

DNS_LABEL_MAX_LEN = 63
DNS_LABEL_REGEX = "[a-z0-9-]{1,%d}$" % DNS_LABEL_MAX_LEN
FQDN_MAX_LEN = 255
DNS_DOMAIN_DEFAULT = 'openstacklocal.'


def _validate_dns_name(data, max_len=FQDN_MAX_LEN):
    msg = _validate_dns_format(data, max_len)
    if msg:
        return msg
    request_dns_name = _get_request_dns_name(data)
    if request_dns_name:
        msg = _validate_dns_name_with_dns_domain(request_dns_name)
        if msg:
            return msg


def _validate_dns_format(data, max_len=FQDN_MAX_LEN):
    # NOTE: An individual name regex instead of an entire FQDN was used
    # because its easier to make correct. The logic should validate that the
    # dns_name matches RFC 1123 (section 2.1) and RFC 952.
    if not data:
        return
    try:
        # Trailing periods are allowed to indicate that a name is fully
        # qualified per RFC 1034 (page 7).
        trimmed = data if not data.endswith('.') else data[:-1]
        if len(trimmed) > 255:
            raise TypeError(
                _("'%s' exceeds the 255 character FQDN limit") % trimmed)
        names = trimmed.split('.')
        for name in names:
            if not name:
                raise TypeError(_("Encountered an empty component."))
            if name.endswith('-') or name[0] == '-':
                raise TypeError(
                    _("Name '%s' must not start or end with a hyphen.") % name)
            if not re.match(DNS_LABEL_REGEX, name):
                raise TypeError(
                    _("Name '%s' must be 1-63 characters long, each of "
                      "which can only be alphanumeric or a hyphen.") % name)
        # RFC 1123 hints that a TLD can't be all numeric. last is a TLD if
        # it's an FQDN.
        if len(names) > 1 and re.match("^[0-9]+$", names[-1]):
            raise TypeError(_("TLD '%s' must not be all numeric") % names[-1])
    except TypeError as e:
        msg = _("'%(data)s' not a valid PQDN or FQDN. Reason: %(reason)s") % {
            'data': data, 'reason': str(e)}
        return msg


def _validate_dns_name_with_dns_domain(request_dns_name):
    # If a PQDN was passed, make sure the FQDN that will be generated is of
    # legal size
    dns_domain = _get_dns_domain()
    higher_labels = dns_domain
    if dns_domain:
        higher_labels = '.%s' % dns_domain
    higher_labels_len = len(higher_labels)
    dns_name_len = len(request_dns_name)
    if not request_dns_name.endswith('.'):
        if dns_name_len + higher_labels_len > FQDN_MAX_LEN:
            msg = _("The dns_name passed is a PQDN and its size is "
                    "'%(dns_name_len)s'. The dns_domain option in "
                    "neutron.conf is set to %(dns_domain)s, with a "
                    "length of '%(higher_labels_len)s'. When the two are "
                    "concatenated to form a FQDN (with a '.' at the end), "
                    "the resulting length exceeds the maximum size "
                    "of '%(fqdn_max_len)s'"
                    ) % {'dns_name_len': dns_name_len,
                         'dns_domain': cfg.CONF.dns_domain,
                         'higher_labels_len': higher_labels_len,
                         'fqdn_max_len': FQDN_MAX_LEN}
            return msg
        return

    # A FQDN was passed
    if (dns_name_len <= higher_labels_len or not
        request_dns_name.endswith(higher_labels)):
        msg = _("The dns_name passed is a FQDN. Its higher level labels "
                "must be equal to the dns_domain option in neutron.conf, "
                "that has been set to '%(dns_domain)s'. It must also "
                "include one or more valid DNS labels to the left "
                "of '%(dns_domain)s'") % {'dns_domain':
                                          cfg.CONF.dns_domain}
        return msg


def _get_dns_domain():
    if not cfg.CONF.dns_domain:
        return ''
    if cfg.CONF.dns_domain.endswith('.'):
        return cfg.CONF.dns_domain
    return '%s.' % cfg.CONF.dns_domain


def _get_request_dns_name(data):
    dns_domain = _get_dns_domain()
    if ((dns_domain and dns_domain != DNS_DOMAIN_DEFAULT)):
        return data
    return ''


def convert_to_lowercase(data):
    if isinstance(data, six.string_types):
        return data.lower()
    msg = _("'%s' cannot be converted to lowercase string") % data
    raise n_exc.InvalidInput(error_message=msg)


attr.validators['type:dns_name'] = (
    _validate_dns_name)


DNSNAME = 'dns_name'
DNSASSIGNMENT = 'dns_assignment'
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        DNSNAME: {'allow_post': True, 'allow_put': True,
                  'default': '',
                  'convert_to': convert_to_lowercase,
                  'validate': {'type:dns_name': FQDN_MAX_LEN},
                  'is_visible': True},
        DNSASSIGNMENT: {'allow_post': False, 'allow_put': False,
                        'is_visible': True},
    }
}


class Dns(extensions.ExtensionDescriptor):
    """Extension class supporting DNS Integration."""

    @classmethod
    def get_name(cls):
        return "DNS Integration"

    @classmethod
    def get_alias(cls):
        return "dns-integration"

    @classmethod
    def get_description(cls):
        return "Provides integration with internal DNS."

    @classmethod
    def get_updated(cls):
        return "2015-08-15T18:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
