# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 Fumihiko Kakuma <kakuma at valinux co jp>
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

from unittest import mock


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
            return self._kwargs[name]

        def __repr__(self):
            args = list(map(repr, self._args))
            kwargs = sorted(['%s=%s' % (x, y) for x, y in
                             self._kwargs.items()])
            return '%s(%s)' % (self._name, ', '.join(args + kwargs))

    return Cls


class _Mod(object):
    _cls_cache = {}

    def __init__(self, name):
        self._name = name

    def __getattr__(self, name):
        fullname = '%s.%s' % (self._name, name)
        if '_' in name:  # constants are named like OFPxxx_yyy_zzz
            return _SimpleValue(fullname)
        try:
            return self._cls_cache[fullname]
        except KeyError:
            pass
        cls = _mkcls(fullname)
        self._cls_cache[fullname] = cls
        return cls

    def __repr__(self):
        return 'Mod(%s)' % (self._name,)


def patch_fake_oflib_of():
    os_ken_mod = mock.Mock()
    os_ken_base_mod = os_ken_mod.base
    os_ken_exc_mod = os_ken_mod.exception
    os_ken_ctrl_mod = os_ken_mod.controller
    handler = _Mod('os_ken.controller.handler')
    handler.set_ev_cls = mock.Mock()
    ofp_event = _Mod('os_ken.controller.ofp_event')
    os_ken_ctrl_mod.handler = handler
    os_ken_ctrl_mod.ofp_event = ofp_event
    os_ken_lib_mod = os_ken_mod.lib
    os_ken_lib_hub = os_ken_lib_mod.hub
    os_ken_packet_mod = os_ken_lib_mod.packet
    packet = _Mod('os_ken.lib.packet.packet')
    arp = _Mod('os_ken.lib.packet.arp')
    ethernet = _Mod('os_ken.lib.packet.ethernet')
    ether_types = _Mod('os_ken.lib.packet.ether_types')
    in_proto = _Mod('os_ken.lib.packet.in_proto')
    icmpv6 = _Mod('os_ken.lib.packet.icmpv6')
    vlan = _Mod('os_ken.lib.packet.vlan')
    os_ken_packet_mod.packet = packet
    packet.Packet = mock.Mock()
    os_ken_packet_mod.arp = arp
    os_ken_packet_mod.ethernet = ethernet
    os_ken_packet_mod.ether_types = ether_types
    os_ken_packet_mod.icmpv6 = icmpv6
    os_ken_packet_mod.in_proto = in_proto
    os_ken_packet_mod.vlan = vlan
    os_ken_ofproto_mod = os_ken_mod.ofproto
    ofp = _Mod('os_ken.ofproto.ofproto_v1_3')
    ofpp = _Mod('os_ken.ofproto.ofproto_v1_3_parser')
    os_ken_ofproto_mod.ofproto_v1_3 = ofp
    os_ken_ofproto_mod.ofproto_v1_3_parser = ofpp
    os_ken_app_mod = os_ken_mod.app
    os_ken_app_ofctl_mod = os_ken_app_mod.ofctl
    os_ken_ofctl_api = os_ken_app_ofctl_mod.api
    modules = {'os_ken': os_ken_mod,
               'os_ken.base': os_ken_base_mod,
               'os_ken.controller': os_ken_ctrl_mod,
               'os_ken.controller.handler': handler,
               'os_ken.controller.handler.set_ev_cls': handler.set_ev_cls,
               'os_ken.controller.ofp_event': ofp_event,
               'os_ken.exception': os_ken_exc_mod,
               'os_ken.lib': os_ken_lib_mod,
               'os_ken.lib.hub': os_ken_lib_hub,
               'os_ken.lib.packet': os_ken_packet_mod,
               'os_ken.lib.packet.packet': packet,
               'os_ken.lib.packet.packet.Packet': packet.Packet,
               'os_ken.lib.packet.arp': arp,
               'os_ken.lib.packet.ethernet': ethernet,
               'os_ken.lib.packet.ether_types': ether_types,
               'os_ken.lib.packet.icmpv6': icmpv6,
               'os_ken.lib.packet.in_proto': in_proto,
               'os_ken.lib.packet.vlan': vlan,
               'os_ken.ofproto': os_ken_ofproto_mod,
               'os_ken.ofproto.ofproto_v1_3': ofp,
               'os_ken.ofproto.ofproto_v1_3_parser': ofpp,
               'os_ken.app': os_ken_app_mod,
               'os_ken.app.ofctl': os_ken_app_ofctl_mod,
               'os_ken.app.ofctl.api': os_ken_ofctl_api}
    return mock.patch.dict('sys.modules', modules)
