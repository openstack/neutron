# Copyright (c) 2014 Cisco Systems
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
#
# @author: Henry Gessau, Cisco Systems

import collections
import time

import requests
import requests.exceptions

from neutron.openstack.common import jsonutils as json
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.cisco.apic import exceptions as cexc


LOG = logging.getLogger(__name__)

APIC_CODE_FORBIDDEN = str(requests.codes.forbidden)


# Info about a Managed Object's relative name (RN) and container.
class ManagedObjectName(collections.namedtuple(
        'MoPath', ['container', 'rn_fmt', 'can_create'])):
    def __new__(cls, container, rn_fmt, can_create=True):
        return super(ManagedObjectName, cls).__new__(cls, container, rn_fmt,
                                                     can_create)


class ManagedObjectClass(object):

    """Information about a Managed Object (MO) class.

    Constructs and keeps track of the distinguished name (DN) and relative
    name (RN) of a managed object (MO) class. The DN is the RN of the MO
    appended to the recursive RNs of its containers, i.e.:
        DN = uni/container-RN/.../container-RN/object-RN

    Also keeps track of whether the MO can be created in the APIC, as some
    MOs are read-only or used for specifying relationships.
    """

    supported_mos = {
        'fvTenant': ManagedObjectName(None, 'tn-%s'),
        'fvBD': ManagedObjectName('fvTenant', 'BD-%s'),
        'fvRsBd': ManagedObjectName('fvAEPg', 'rsbd'),
        'fvSubnet': ManagedObjectName('fvBD', 'subnet-[%s]'),
        'fvCtx': ManagedObjectName('fvTenant', 'ctx-%s'),
        'fvRsCtx': ManagedObjectName('fvBD', 'rsctx'),
        'fvAp': ManagedObjectName('fvTenant', 'ap-%s'),
        'fvAEPg': ManagedObjectName('fvAp', 'epg-%s'),
        'fvRsProv': ManagedObjectName('fvAEPg', 'rsprov-%s'),
        'fvRsCons': ManagedObjectName('fvAEPg', 'rscons-%s'),
        'fvRsConsIf': ManagedObjectName('fvAEPg', 'rsconsif-%s'),
        'fvRsDomAtt': ManagedObjectName('fvAEPg', 'rsdomAtt-[%s]'),
        'fvRsPathAtt': ManagedObjectName('fvAEPg', 'rspathAtt-[%s]'),

        'vzBrCP': ManagedObjectName('fvTenant', 'brc-%s'),
        'vzSubj': ManagedObjectName('vzBrCP', 'subj-%s'),
        'vzFilter': ManagedObjectName('fvTenant', 'flt-%s'),
        'vzRsFiltAtt': ManagedObjectName('vzSubj', 'rsfiltAtt-%s'),
        'vzEntry': ManagedObjectName('vzFilter', 'e-%s'),
        'vzInTerm': ManagedObjectName('vzSubj', 'intmnl'),
        'vzRsFiltAtt__In': ManagedObjectName('vzInTerm', 'rsfiltAtt-%s'),
        'vzOutTerm': ManagedObjectName('vzSubj', 'outtmnl'),
        'vzRsFiltAtt__Out': ManagedObjectName('vzOutTerm', 'rsfiltAtt-%s'),
        'vzCPIf': ManagedObjectName('fvTenant', 'cif-%s'),
        'vzRsIf': ManagedObjectName('vzCPIf', 'rsif'),

        'vmmProvP': ManagedObjectName(None, 'vmmp-%s', False),
        'vmmDomP': ManagedObjectName('vmmProvP', 'dom-%s'),
        'vmmEpPD': ManagedObjectName('vmmDomP', 'eppd-[%s]'),

        'physDomP': ManagedObjectName(None, 'phys-%s'),

        'infra': ManagedObjectName(None, 'infra'),
        'infraNodeP': ManagedObjectName('infra', 'nprof-%s'),
        'infraLeafS': ManagedObjectName('infraNodeP', 'leaves-%s-typ-%s'),
        'infraNodeBlk': ManagedObjectName('infraLeafS', 'nodeblk-%s'),
        'infraRsAccPortP': ManagedObjectName('infraNodeP', 'rsaccPortP-[%s]'),
        'infraAccPortP': ManagedObjectName('infra', 'accportprof-%s'),
        'infraHPortS': ManagedObjectName('infraAccPortP', 'hports-%s-typ-%s'),
        'infraPortBlk': ManagedObjectName('infraHPortS', 'portblk-%s'),
        'infraRsAccBaseGrp': ManagedObjectName('infraHPortS', 'rsaccBaseGrp'),
        'infraFuncP': ManagedObjectName('infra', 'funcprof'),
        'infraAccPortGrp': ManagedObjectName('infraFuncP', 'accportgrp-%s'),
        'infraRsAttEntP': ManagedObjectName('infraAccPortGrp', 'rsattEntP'),
        'infraAttEntityP': ManagedObjectName('infra', 'attentp-%s'),
        'infraRsDomP': ManagedObjectName('infraAttEntityP', 'rsdomP-[%s]'),
        'infraRsVlanNs__phys': ManagedObjectName('physDomP', 'rsvlanNs'),
        'infraRsVlanNs__vmm': ManagedObjectName('vmmDomP', 'rsvlanNs'),

        'fvnsVlanInstP': ManagedObjectName('infra', 'vlanns-%s-%s'),
        'fvnsEncapBlk__vlan': ManagedObjectName('fvnsVlanInstP',
                                                'from-%s-to-%s'),
        'fvnsVxlanInstP': ManagedObjectName('infra', 'vxlanns-%s'),
        'fvnsEncapBlk__vxlan': ManagedObjectName('fvnsVxlanInstP',
                                                 'from-%s-to-%s'),

        # Read-only
        'fabricTopology': ManagedObjectName(None, 'topology', False),
        'fabricPod': ManagedObjectName('fabricTopology', 'pod-%s', False),
        'fabricPathEpCont': ManagedObjectName('fabricPod', 'paths-%s', False),
        'fabricPathEp': ManagedObjectName('fabricPathEpCont', 'pathep-%s',
                                          False),
    }

    # Note(Henry): The use of a mutable default argument _inst_cache is
    # intentional. It persists for the life of MoClass to cache instances.
    # noinspection PyDefaultArgument
    def __new__(cls, mo_class, _inst_cache={}):
        """Ensure we create only one instance per mo_class."""
        try:
            return _inst_cache[mo_class]
        except KeyError:
            new_inst = super(ManagedObjectClass, cls).__new__(cls)
            new_inst.__init__(mo_class)
            _inst_cache[mo_class] = new_inst
            return new_inst

    def __init__(self, mo_class):
        self.klass = mo_class
        self.klass_name = mo_class.split('__')[0]
        mo = self.supported_mos[mo_class]
        self.container = mo.container
        self.rn_fmt = mo.rn_fmt
        self.dn_fmt, self.args = self._dn_fmt()
        self.arg_count = self.dn_fmt.count('%s')
        rn_has_arg = self.rn_fmt.count('%s')
        self.can_create = rn_has_arg and mo.can_create

    def _dn_fmt(self):
        """Build the distinguished name format using container and RN.

        DN = uni/container-RN/.../container-RN/object-RN

        Also make a list of the required name arguments.
        Note: Call this method only once at init.
        """
        arg = [self.klass] if '%s' in self.rn_fmt else []
        if self.container:
            container = ManagedObjectClass(self.container)
            dn_fmt = '%s/%s' % (container.dn_fmt, self.rn_fmt)
            args = container.args + arg
            return dn_fmt, args
        return 'uni/%s' % self.rn_fmt, arg

    def dn(self, *args):
        """Return the distinguished name for a managed object."""
        return self.dn_fmt % args


class ApicSession(object):

    """Manages a session with the APIC."""

    def __init__(self, host, port, usr, pwd, ssl):
        protocol = ssl and 'https' or 'http'
        self.api_base = '%s://%s:%s/api' % (protocol, host, port)
        self.session = requests.Session()
        self.session_deadline = 0
        self.session_timeout = 0
        self.cookie = {}

        # Log in
        self.authentication = None
        self.username = None
        self.password = None
        if usr and pwd:
            self.login(usr, pwd)

    @staticmethod
    def _make_data(key, **attrs):
        """Build the body for a msg out of a key and some attributes."""
        return json.dumps({key: {'attributes': attrs}})

    def _api_url(self, api):
        """Create the URL for a generic API."""
        return '%s/%s.json' % (self.api_base, api)

    def _mo_url(self, mo, *args):
        """Create a URL for a MO lookup by DN."""
        dn = mo.dn(*args)
        return '%s/mo/%s.json' % (self.api_base, dn)

    def _qry_url(self, mo):
        """Create a URL for a query lookup by MO class."""
        return '%s/class/%s.json' % (self.api_base, mo.klass_name)

    def _check_session(self):
        """Check that we are logged in and ensure the session is active."""
        if not self.authentication:
            raise cexc.ApicSessionNotLoggedIn
        if time.time() > self.session_deadline:
            self.refresh()

    def _send(self, request, url, data=None, refreshed=None):
        """Send a request and process the response."""
        if data is None:
            response = request(url, cookies=self.cookie)
        else:
            response = request(url, data=data, cookies=self.cookie)
        if response is None:
            raise cexc.ApicHostNoResponse(url=url)
        # Every request refreshes the timeout
        self.session_deadline = time.time() + self.session_timeout
        if data is None:
            request_str = url
        else:
            request_str = '%s, data=%s' % (url, data)
            LOG.debug(_("data = %s"), data)
        # imdata is where the APIC returns the useful information
        imdata = response.json().get('imdata')
        LOG.debug(_("Response: %s"), imdata)
        if response.status_code != requests.codes.ok:
            try:
                err_code = imdata[0]['error']['attributes']['code']
                err_text = imdata[0]['error']['attributes']['text']
            except (IndexError, KeyError):
                err_code = '[code for APIC error not found]'
                err_text = '[text for APIC error not found]'
            # If invalid token then re-login and retry once
            if (not refreshed and err_code == APIC_CODE_FORBIDDEN and
                    err_text.lower().startswith('token was invalid')):
                self.login()
                return self._send(request, url, data=data, refreshed=True)
            raise cexc.ApicResponseNotOk(request=request_str,
                                         status=response.status_code,
                                         reason=response.reason,
                                         err_text=err_text, err_code=err_code)
        return imdata

    # REST requests

    def get_data(self, request):
        """Retrieve generic data from the server."""
        self._check_session()
        url = self._api_url(request)
        return self._send(self.session.get, url)

    def get_mo(self, mo, *args):
        """Retrieve a managed object by its distinguished name."""
        self._check_session()
        url = self._mo_url(mo, *args) + '?query-target=self'
        return self._send(self.session.get, url)

    def list_mo(self, mo):
        """Retrieve the list of managed objects for a class."""
        self._check_session()
        url = self._qry_url(mo)
        return self._send(self.session.get, url)

    def post_data(self, request, data):
        """Post generic data to the server."""
        self._check_session()
        url = self._api_url(request)
        return self._send(self.session.post, url, data=data)

    def post_mo(self, mo, *args, **kwargs):
        """Post data for a managed object to the server."""
        self._check_session()
        url = self._mo_url(mo, *args)
        data = self._make_data(mo.klass_name, **kwargs)
        return self._send(self.session.post, url, data=data)

    # Session management

    def _save_cookie(self, request, response):
        """Save the session cookie and its expiration time."""
        imdata = response.json().get('imdata')
        if response.status_code == requests.codes.ok:
            attributes = imdata[0]['aaaLogin']['attributes']
            try:
                self.cookie = {'APIC-Cookie': attributes['token']}
            except KeyError:
                raise cexc.ApicResponseNoCookie(request=request)
            timeout = int(attributes['refreshTimeoutSeconds'])
            LOG.debug(_("APIC session will expire in %d seconds"), timeout)
            # Give ourselves a few seconds to refresh before timing out
            self.session_timeout = timeout - 5
            self.session_deadline = time.time() + self.session_timeout
        else:
            attributes = imdata[0]['error']['attributes']
        return attributes

    def login(self, usr=None, pwd=None):
        """Log in to controller. Save user name and authentication."""
        usr = usr or self.username
        pwd = pwd or self.password
        name_pwd = self._make_data('aaaUser', name=usr, pwd=pwd)
        url = self._api_url('aaaLogin')
        try:
            response = self.session.post(url, data=name_pwd, timeout=10.0)
        except requests.exceptions.Timeout:
            raise cexc.ApicHostNoResponse(url=url)
        attributes = self._save_cookie('aaaLogin', response)
        if response.status_code == requests.codes.ok:
            self.username = usr
            self.password = pwd
            self.authentication = attributes
        else:
            self.authentication = None
            raise cexc.ApicResponseNotOk(request=url,
                                         status=response.status_code,
                                         reason=response.reason,
                                         err_text=attributes['text'],
                                         err_code=attributes['code'])

    def refresh(self):
        """Called when a session has timed out or almost timed out."""
        url = self._api_url('aaaRefresh')
        response = self.session.get(url, cookies=self.cookie)
        attributes = self._save_cookie('aaaRefresh', response)
        if response.status_code == requests.codes.ok:
            # We refreshed before the session timed out.
            self.authentication = attributes
        else:
            err_code = attributes['code']
            err_text = attributes['text']
            if (err_code == APIC_CODE_FORBIDDEN and
                    err_text.lower().startswith('token was invalid')):
                # This means the token timed out, so log in again.
                LOG.debug(_("APIC session timed-out, logging in again."))
                self.login()
            else:
                self.authentication = None
                raise cexc.ApicResponseNotOk(request=url,
                                             status=response.status_code,
                                             reason=response.reason,
                                             err_text=err_text,
                                             err_code=err_code)

    def logout(self):
        """End session with controller."""
        if not self.username:
            self.authentication = None
        if self.authentication:
            data = self._make_data('aaaUser', name=self.username)
            self.post_data('aaaLogout', data=data)
        self.authentication = None


class ManagedObjectAccess(object):

    """CRUD operations on APIC Managed Objects."""

    def __init__(self, session, mo_class):
        self.session = session
        self.mo = ManagedObjectClass(mo_class)

    def _create_container(self, *args):
        """Recursively create all container objects."""
        if self.mo.container:
            container = ManagedObjectAccess(self.session, self.mo.container)
            if container.mo.can_create:
                container_args = args[0: container.mo.arg_count]
                container._create_container(*container_args)
                container.session.post_mo(container.mo, *container_args)

    def create(self, *args, **kwargs):
        self._create_container(*args)
        if self.mo.can_create and 'status' not in kwargs:
            kwargs['status'] = 'created'
        return self.session.post_mo(self.mo, *args, **kwargs)

    def _mo_attributes(self, obj_data):
        if (self.mo.klass_name in obj_data and
                'attributes' in obj_data[self.mo.klass_name]):
            return obj_data[self.mo.klass_name]['attributes']

    def get(self, *args):
        """Return a dict of the MO's attributes, or None."""
        imdata = self.session.get_mo(self.mo, *args)
        if imdata:
            return self._mo_attributes(imdata[0])

    def list_all(self):
        imdata = self.session.list_mo(self.mo)
        return filter(None, [self._mo_attributes(obj) for obj in imdata])

    def list_names(self):
        return [obj['name'] for obj in self.list_all()]

    def update(self, *args, **kwargs):
        return self.session.post_mo(self.mo, *args, **kwargs)

    def delete(self, *args):
        return self.session.post_mo(self.mo, *args, status='deleted')


class RestClient(ApicSession):

    """APIC REST client for OpenStack Neutron."""

    def __init__(self, host, port=80, usr=None, pwd=None, ssl=False):
        """Establish a session with the APIC."""
        super(RestClient, self).__init__(host, port, usr, pwd, ssl)

    def __getattr__(self, mo_class):
        """Add supported MOs as properties on demand."""
        if mo_class not in ManagedObjectClass.supported_mos:
            raise cexc.ApicManagedObjectNotSupported(mo_class=mo_class)
        self.__dict__[mo_class] = ManagedObjectAccess(self, mo_class)
        return self.__dict__[mo_class]
