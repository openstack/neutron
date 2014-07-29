# Copyright (C) 2014 VA Linux Systems Japan K.K.
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
# @author: Fumihiko Kakuma, VA Linux Systems Japan K.K.
# @author: YAMAMOTO Takashi, VA Linux Systems Japan K.K.

import mock


class _Eq(object):
    def __eq__(self, other):
        return repr(self) == repr(other)

    def __ne__(self, other):
        return not self.__eq__(other)


class _Value(_Eq):
    def __or__(self, b):
        return _Op('|', self, b)

    def __ror__(self, a):
        return _Op('|', a, self)


class _SimpleValue(_Value):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name


class _Op(_Value):
    def __init__(self, op, a, b):
        self.op = op
        self.a = a
        self.b = b

    def __repr__(self):
        return '%s%s%s' % (self.a, self.op, self.b)


def _mkcls(name):
    class Cls(_Eq):
        _name = name

        def __init__(self, *args, **kwargs):
            self._args = args
            self._kwargs = kwargs
            self._hist = []

        def __getattr__(self, name):
            return name

        def __repr__(self):
            args = map(repr, self._args)
            kwargs = sorted(['%s=%s' % (x, y) for x, y in
                             self._kwargs.items()])
            return '%s(%s)' % (self._name, ', '.join(args + kwargs))

    return Cls


class _Mod(object):
    def __init__(self, name):
        self._name = name

    def __getattr__(self, name):
        fullname = '%s.%s' % (self._name, name)
        if '_' in name:  # constants are named like OFPxxx_yyy_zzz
            return _SimpleValue(fullname)
        return _mkcls(fullname)

    def __repr__(self):
        return 'Mod(%s)' % (self._name,)


def patch_fake_oflib_of():
    ryu_mod = mock.Mock()
    ryu_base_mod = ryu_mod.base
    ryu_lib_mod = ryu_mod.lib
    ryu_lib_hub = ryu_lib_mod.hub
    ryu_ofproto_mod = ryu_mod.ofproto
    ofp = _Mod('ryu.ofproto.ofproto_v1_3')
    ofpp = _Mod('ryu.ofproto.ofproto_v1_3_parser')
    ryu_ofproto_mod.ofproto_v1_3 = ofp
    ryu_ofproto_mod.ofproto_v1_3_parser = ofpp
    ryu_app_mod = ryu_mod.app
    ryu_app_ofctl_mod = ryu_app_mod.ofctl
    ryu_ofctl_api = ryu_app_ofctl_mod.api
    modules = {'ryu': ryu_mod,
               'ryu.base': ryu_base_mod,
               'ryu.lib': ryu_lib_mod,
               'ryu.lib.hub': ryu_lib_hub,
               'ryu.ofproto': ryu_ofproto_mod,
               'ryu.ofproto.ofproto_v1_3': ofp,
               'ryu.ofproto.ofproto_v1_3_parser': ofpp,
               'ryu.app': ryu_app_mod,
               'ryu.app.ofctl': ryu_app_ofctl_mod,
               'ryu.app.ofctl.api': ryu_ofctl_api}
    return mock.patch.dict('sys.modules', modules)
