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

import enum


ADD_BGP_ROUTER = """\
{{ bgp_router_config }}
!
{% if bgp_af_ipv4_unicast %}
{{ bgp_af_ipv4_unicast }}
{% endif %}
!
{% if bgp_af_ipv6_unicast %}
{{ bgp_af_ipv6_unicast }}
{% endif %}
!
{% if bgp_af_l2vpn_evpn %}
{{ bgp_af_l2vpn_evpn }}
{% endif %}
exit
"""

ADD_EVPN_ROUTER = """\
vrf {{ vrf_name }}
 vni {{ vni }}
exit-vrf
!
{{ evpn_router_config }}
!
{% if evpn_af_ipv4_unicast %}
{{ evpn_af_ipv4_unicast }}
{% endif %}
!
{% if evpn_af_ipv6_unicast %}
{{ evpn_af_ipv6_unicast }}
{% endif %}
!
{% if evpn_af_l2vpn_evpn %}
{{ evpn_af_l2vpn_evpn }}
{% endif %}
exit
"""

DEL_BGP_ROUTER = """\
no router bgp {{ asn }}
"""

DEL_EVPN_ROUTER = """\
vrf {{ vrf_name }}
 no vni {{ vni }}
exit-vrf
!
no router bgp {{ asn }} vrf {{ vrf_name }}
!
no vrf {{ vrf_name }}
"""

BGP_ROUTER_CONFIG = """\
router bgp {{ asn }}
 bgp router-id {{ bgp_router_id }}
 no bgp ebgp-requires-policy
 neighbor {{ peer_interface }} interface remote-as internal
"""

BGP_AF_IPV4_UNICAST = """\
 address-family ipv4 unicast
  neighbor {{ peer_interface }} activate
  redistribute connected
 exit-address-family
"""

BGP_AF_IPV6_UNICAST = """\
 address-family ipv6 unicast
  neighbor {{ peer_interface }} activate
  redistribute connected
 exit-address-family
"""

BGP_AF_L2VPN_EVPN = """\
 address-family l2vpn evpn
  neighbor {{ peer_interface }} activate
  advertise-all-vni
  advertise-svi-ip
 exit-address-family
"""

EVPN_ROUTER_CONFIG = """\
router bgp {{ asn }} vrf {{ vrf_name }}
 bgp router-id {{ bgp_router_id }}
 no bgp ebgp-requires-policy
"""

EVPN_AF_IPV4_UNICAST = """\
 address-family ipv4 unicast
  redistribute kernel
 exit-address-family
"""

EVPN_AF_IPV6_UNICAST = """\
 address-family ipv6 unicast
  redistribute kernel
 exit-address-family
"""

EVPN_AF_L2VPN_EVPN = """\
 address-family l2vpn evpn
  advertise ipv4 unicast
  advertise ipv6 unicast
 exit-address-family
"""


class TmplName(enum.StrEnum):
    ADD_BGP_ROUTER = 'add_bgp_router'
    ADD_EVPN_ROUTER = 'add_evpn_router'
    DEL_BGP_ROUTER = 'del_bgp_router'
    DEL_EVPN_ROUTER = 'del_evpn_router'
    BGP_ROUTER_CONFIG = 'bgp_router_config'
    BGP_AF_IPV4_UNICAST = 'bgp_af_ipv4_unicast'
    BGP_AF_IPV6_UNICAST = 'bgp_af_ipv6_unicast'
    BGP_AF_L2VPN_EVPN = 'bgp_af_l2vpn_evpn'
    EVPN_ROUTER_CONFIG = 'evpn_router_config'
    EVPN_AF_IPV4_UNICAST = 'evpn_af_ipv4_unicast'
    EVPN_AF_IPV6_UNICAST = 'evpn_af_ipv6_unicast'
    EVPN_AF_L2VPN_EVPN = 'evpn_af_l2vpn_evpn'


TMPL_MAP: dict[str, str] = {
    TmplName.ADD_BGP_ROUTER: ADD_BGP_ROUTER,
    TmplName.ADD_EVPN_ROUTER: ADD_EVPN_ROUTER,
    TmplName.DEL_BGP_ROUTER: DEL_BGP_ROUTER,
    TmplName.DEL_EVPN_ROUTER: DEL_EVPN_ROUTER,
    TmplName.BGP_ROUTER_CONFIG: BGP_ROUTER_CONFIG,
    TmplName.BGP_AF_IPV4_UNICAST: BGP_AF_IPV4_UNICAST,
    TmplName.BGP_AF_IPV6_UNICAST: BGP_AF_IPV6_UNICAST,
    TmplName.BGP_AF_L2VPN_EVPN: BGP_AF_L2VPN_EVPN,
    TmplName.EVPN_ROUTER_CONFIG: EVPN_ROUTER_CONFIG,
    TmplName.EVPN_AF_IPV4_UNICAST: EVPN_AF_IPV4_UNICAST,
    TmplName.EVPN_AF_IPV6_UNICAST: EVPN_AF_IPV6_UNICAST,
    TmplName.EVPN_AF_L2VPN_EVPN: EVPN_AF_L2VPN_EVPN,
}
