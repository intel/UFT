#! /usr/bin/ python
# Copyright(c) 2021 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
from enum import Enum, unique
from sqlite3 import collections

UINT32_MAX = 0xffffffff

@unique
class rte_flow_item_type(Enum):
    RTE_FLOW_ITEM_TYPE_END      = 0
    RTE_FLOW_ITEM_TYPE_VOID     = 1
    RTE_FLOW_ITEM_TYPE_INVERT   = 2
    RTE_FLOW_ITEM_TYPE_ANY      = 3
    RTE_FLOW_ITEM_TYPE_PF       = 4
    RTE_FLOW_ITEM_TYPE_VF       = 5
    RTE_FLOW_ITEM_TYPE_PHY_PORT = 6
    RTE_FLOW_ITEM_TYPE_PORT_ID  = 7
    RTE_FLOW_ITEM_TYPE_RAW      = 8
    RTE_FLOW_ITEM_TYPE_ETH      = 9
    RTE_FLOW_ITEM_TYPE_VLAN     = 10
    RTE_FLOW_ITEM_TYPE_IPV4     = 11
    RTE_FLOW_ITEM_TYPE_IPV6     = 12
    RTE_FLOW_ITEM_TYPE_ICMP     = 13
    RTE_FLOW_ITEM_TYPE_UDP      = 14
    RTE_FLOW_ITEM_TYPE_TCP      = 15
    RTE_FLOW_ITEM_TYPE_SCTP     = 16
    RTE_FLOW_ITEM_TYPE_VXLAN    = 17
    RTE_FLOW_ITEM_TYPE_E_TAG    = 18
    RTE_FLOW_ITEM_TYPE_NVGRE    = 19
    RTE_FLOW_ITEM_TYPE_MPLS     = 20
    RTE_FLOW_ITEM_TYPE_GRE      = 21
    RTE_FLOW_ITEM_TYPE_FUZZY    = 22
    RTE_FLOW_ITEM_TYPE_GTP      = 23
    RTE_FLOW_ITEM_TYPE_GTPC     = 24
    RTE_FLOW_ITEM_TYPE_GTPU     = 25
    RTE_FLOW_ITEM_TYPE_ESP      = 26
    RTE_FLOW_ITEM_TYPE_GENEVE   = 27
    RTE_FLOW_ITEM_TYPE_VXLAN_GPE= 28
    RTE_FLOW_ITEM_TYPE_ARP_ETH_IPV4 = 29
    RTE_FLOW_ITEM_TYPE_IPV6_EXT = 30
    RTE_FLOW_ITEM_TYPE_ICMP6    = 31
    RTE_FLOW_ITEM_TYPE_ICMP6_ND_NS=32
    RTE_FLOW_ITEM_TYPE_ICMP6_ND_NA=33
    RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT=34
    RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_SLA_ETH=35
    RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_TLA_ETH=36
    RTE_FLOW_ITEM_TYPE_MARK     = 37
    RTE_FLOW_ITEM_TYPE_META     = 38
    RTE_FLOW_ITEM_TYPE_GRE_KEY  = 39
    RTE_FLOW_ITEM_TYPE_GTP_PSC  = 40
    RTE_FLOW_ITEM_TYPE_PPPOES   = 41
    RTE_FLOW_ITEM_TYPE_PPPOED   = 42
    RTE_FLOW_ITEM_TYPE_PPPOE_PROTO_ID= 43
    RTE_FLOW_ITEM_TYPE_NSH      = 44
    RTE_FLOW_ITEM_TYPE_IGMP     = 45
    RTE_FLOW_ITEM_TYPE_AH       = 46
    RTE_FLOW_ITEM_TYPE_HIGIG2   = 47
    RTE_FLOW_ITEM_TYPE_TAG      = 48

# RTE_FLOW_ITEM_TYPE_ANY
rte_flow_item_any = collections.namedtuple('rte_flow_item_any', ['num'])
rte_flow_item_any.__new__.__defaults__ = (0x00000000,)
# Default mask for RTE_FLOW_ITEM_TYPE_ANY.
rte_flow_item_any_mask = rte_flow_item_any(num=0x00000000,)

# RTE_FLOW_ITEM_TYPE_VF
rte_flow_item_vf = collections.namedtuple('rte_flow_item_vf', ['id'])
rte_flow_item_vf.__new__.__defaults__ = (0x00000000,)
# Default mask for RTE_FLOW_ITEM_TYPE_VF.
rte_flow_item_vf_mask = rte_flow_item_vf(id=0x00000000)

# RTE_FLOW_ITEM_TYPE_PHY_PORT
rte_flow_item_phy_port = collections.namedtuple('rte_flow_item_phy_port', ['index'])
rte_flow_item_phy_port.__new__.__defaults__ = (0x00000000,)
# Default mask for RTE_FLOW_ITEM_TYPE_PHY_PORT.
rte_flow_item_phy_port_mask = rte_flow_item_phy_port(index=0x00000000)

# RTE_FLOW_ITEM_TYPE_PORT_ID
rte_flow_item_port_id = collections.namedtuple('rte_flow_item_port_id', ['id'])
rte_flow_item_port_id.__new__.__defaults__ = (0,)
# Default mask for RTE_FLOW_ITEM_TYPE_PORT_ID.
rte_flow_item_port_id_mask = rte_flow_item_port_id(id=0xffffffff)

# RTE_FLOW_ITEM_TYPE_RAW
rte_flow_item_raw = collections.namedtuple('rte_flow_item_raw', ['relative', 'search', 'reserved', 'offset', 'limit', 'length', 'pattern'])
rte_flow_item_raw.__new__.__defaults__ = (0, 0, 0, 0, 0, 0, None)
# Default mask for RTE_FLOW_ITEM_TYPE_RAW.
rte_flow_item_raw_mask = rte_flow_item_raw(1, 1, 0x3fffffff, 0xffffffff, 0xffff, 0xffff, None)

# header ether addr
rte_ether_addr = collections.namedtuple('rte_ether_addr', ['addr_bytes'])
rte_ether_addr.__new__.__defaults__ = (b'',)
# RTE_FLOW_ITEM_TYPE_ETH
rte_flow_item_eth = collections.namedtuple('rte_flow_item_eth', ['dst', 'src', 'type_'])
rte_flow_item_eth.__new__.__defaults__ = (rte_ether_addr(), rte_ether_addr(), 0x0)
# Default mask for RTE_FLOW_ITEM_TYPE_ETH.
rte_flow_item_eth_mask = rte_flow_item_eth(rte_ether_addr(addr_bytes=b"\xff\xff\xff\xff\xff\xff"),
                                   rte_ether_addr(addr_bytes=b"\xff\xff\xff\xff\xff\xff"), 0x0000)

# RTE_FLOW_ITEM_TYPE_VLAN
rte_flow_item_vlan = collections.namedtuple('rte_flow_item_vlan', ['tci', 'inner_type'])
rte_flow_item_vlan.__new__.__defaults__ = (0x0, 0x0)
# Default mask for RTE_FLOW_ITEM_TYPE_ETH.
rte_flow_item_vlan_mask = rte_flow_item_vlan(0x0fff, 0x0000)

# header ipv4
rte_ipv4_hdr = collections.namedtuple('rte_ipv4_hdr', ['version_ihl', 'type_of_service', 'total_length', 'packet_id',
                                               'fragment_offset', 'time_to_live', 'next_proto_id', 'hdr_checksum',
                                               'src_addr', 'dst_addr'])
rte_ipv4_hdr.__new__.__defaults__ = (0, 0, 0, 0, 0, 64, 0, 0, 0, 0)
# RTE_FLOW_ITEM_TYPE_IPV4
rte_flow_item_ipv4 = collections.namedtuple('rte_flow_item_ipv4', ['hdr'])
rte_flow_item_ipv4.__new__.__defaults__ = (rte_ipv4_hdr(),)
# Default mask for RTE_FLOW_ITEM_TYPE_IPV4.
rte_flow_item_ipv4_mask = rte_flow_item_ipv4(rte_ipv4_hdr(src_addr=0xffff, dst_addr=0xffff))

# header ipv6
rte_ipv6_hdr = collections.namedtuple('rte_ipv6_hdr', ['vtc_flow', 'payload_len', 'proto', 'hop_limits',
                                               'src_addr', 'dst_addr'])
rte_ipv6_hdr.__new__.__defaults__ = (0, 0, 0, 0, b'',b'',)
# RTE_FLOW_ITEM_TYPE_IPV6
rte_flow_item_ipv6 = collections.namedtuple('rte_flow_item_ipv6', ['hdr'])
rte_flow_item_ipv6.__new__.__defaults__ = (rte_ipv6_hdr(),)
# Default mask for RTE_FLOW_ITEM_TYPE_IPV6.
rte_flow_item_ipv6_mask = rte_flow_item_ipv6(rte_ipv6_hdr(src_addr=b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                                              dst_addr=b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"))

# header icmp
rte_icmp_hdr = collections.namedtuple("rte_icmp_hdr", ['icmp_type', 'icmp_code', 'icmp_cksum', 'icmp_ident', 'icmp_seq_nb'])
rte_icmp_hdr.__new__.__defaults__ = (0, 0, 0, 0, 0)
# RTE_FLOW_ITEM_TYPE_ICMP
rte_flow_item_icmp = collections.namedtuple('rte_flow_item_icmp', ['hdr'])
rte_flow_item_icmp.__new__.__defaults__ = (rte_icmp_hdr(),)
# Default mask for RTE_FLOW_ITEM_TYPE_ICMP.
rte_flow_item_icmp_mask = rte_flow_item_icmp(rte_icmp_hdr(icmp_type=0xff, icmp_code=0xff))

# header udp
rte_udp_hdr = collections.namedtuple("rte_udp_hdr", ['src_port', 'dst_port', 'dgram_len', 'dgram_cksum'])
rte_udp_hdr.__new__.__defaults__ = (53, 53, 0, 0)
# RTE_FLOW_ITEM_TYPE_UDP
rte_flow_item_udp = collections.namedtuple('rte_flow_item_udp', ['hdr'])
rte_flow_item_udp.__new__.__defaults__ = (rte_udp_hdr(),)
# Default mask for RTE_FLOW_ITEM_TYPE_UDP.
rte_flow_item_udp_mask = rte_flow_item_udp(rte_udp_hdr(src_port=0xffff, dst_port=0xffff))

# header tcp
rte_tcp_hdr = collections.namedtuple('rte_tcp_hdr', ['src_port', 'dst_port', 'sent_seq', 'recv_ack', 'data_off',
                                             'tcp_flags', 'rx_win', 'cksum', 'tcp_urp'])
rte_tcp_hdr.__new__.__defaults__ = (53, 53, 0, 0, 0, 0, 0, 0, 0)
# RTE_FLOW_ITEM_TYPE_TCP
rte_flow_item_tcp = collections.namedtuple("rte_flow_item_tcp", ['hdr'])
rte_flow_item_tcp.__new__.__defaults__ = (rte_tcp_hdr(),)
# Default mask for RTE_FLOW_ITEM_TYPE_TCP.
rte_flow_item_tcp_mask = rte_flow_item_tcp(rte_tcp_hdr(src_port=0xffff, dst_port=0xffff))

# header sctp
rte_sctp_hdr = collections.namedtuple('rte_sctp_hdr', ['src_port', 'dst_port', 'tag', 'cksum'])
rte_sctp_hdr.__new__.__defaults__ = (53, 53, 0, 0)
# RTE_FLOW_ITEM_TYPE_SCTP
rte_flow_item_sctp = collections.namedtuple('rte_flow_item_sctp', ['hdr'])
rte_flow_item_sctp.__new__.__defaults__ = (rte_sctp_hdr(),)
# Default mask for RTE_FLOW_ITEM_TYPE_SCTP.
rte_flow_item_sctp_mask = rte_flow_item_sctp(rte_sctp_hdr(src_port=0xffff, dst_port=0xffff))

# RTE_FLOW_ITEM_TYPE_VXLAN
rte_flow_item_vxlan = collections.namedtuple('rte_flow_item_vxlan', ['flags', 'rsvd0', 'vni', 'rsvd1'])
rte_flow_item_vxlan.__new__.__defaults__ = (0, b'', b'', 0)
# Default mask for RTE_FLOW_ITEM_TYPE_VXLAN.
rte_flow_item_vxlan_mask = rte_flow_item_vxlan(vni=b'\xff\xff\xff')

# RTE_FLOW_ITEM_TYPE_E_TAG
rte_flow_item_e_tag = collections.namedtuple('rte_flow_item_e_tag', ['epcp_edei_in_ecid_b', 'rsvd_grp_ecid_b',
                                                             'in_ecid_e', 'ecid_e', 'inner_type'])
rte_flow_item_e_tag.__new__.__defaults__ = (0, 0, 0, 0, 0)
# Default mask for RTE_FLOW_ITEM_TYPE_E_TAG.
rte_flow_item_e_tag_mask = rte_flow_item_e_tag(rsvd_grp_ecid_b=0x3fff)

# RTE_FLOW_ITEM_TYPE_NVGRE
rte_flow_item_nvgre = collections.namedtuple('rte_flow_item_nvgre', ['c_k_s_rsvd0_ver', 'protocol', 'tni', 'flow_id'])
rte_flow_item_nvgre.__new__.__defaults__ = (0, 0, b'', 0)
# Default mask for RTE_FLOW_ITEM_TYPE_NVGRE.
rte_flow_item_nvgre_mask = rte_flow_item_nvgre(tni=b'\xff\xff\xff')

# RTE_FLOW_ITEM_TYPE_MPLS
rte_flow_item_mpls = collections.namedtuple('rte_flow_item_mpls', ['label_tc_s', 'ttl'])
rte_flow_item_mpls.__new__.__defaults__ = (b'', 0)
# Default mask for RTE_FLOW_ITEM_TYPE_MPLS.
rte_flow_item_mpls_mask = rte_flow_item_mpls(label_tc_s=b'\xff\xff\xf0')

# RTE_FLOW_ITEM_TYPE_GRE
rte_flow_item_gre = collections.namedtuple('rte_flow_item_gre', ['c_rsvd0_ver', 'protocol'])
rte_flow_item_gre.__new__.__defaults__ = (0, 0)
# Default mask for RTE_FLOW_ITEM_TYPE_GRE.
rte_flow_item_gre_mask = rte_flow_item_gre(protocol=0xffff)

# RTE_FLOW_ITEM_TYPE_FUZZY
rte_flow_item_fuzzy = collections.namedtuple('rte_flow_item_fuzzy', ['thresh'])
rte_flow_item_fuzzy.__new__.__defaults__ = (0x0,)
# Default mask for RTE_FLOW_ITEM_TYPE_FUZZY.
rte_flow_item_fuzzy_mask = rte_flow_item_fuzzy(thresh=0xffffffff)

# RTE_FLOW_ITEM_TYPE_GTP
rte_flow_item_gtp = collections.namedtuple('rte_flow_item_gtp', ['v_pt_rsv_flags', 'msg_type', 'msg_len', 'teid'])
rte_flow_item_gtp.__new__.__defaults__ = (0, 0, 0, 0x0)
# efault mask for RTE_FLOW_ITEM_TYPE_GTP.
rte_flow_item_gtp_mask = rte_flow_item_gtp(teid=0xffffffff)

# header esp
rte_esp_hdr = collections.namedtuple('rte_esp_hdr', ['spi', 'seq'])
rte_esp_hdr.__new__.__defaults__ = (0, 0)
# RTE_FLOW_ITEM_TYPE_ESP
rte_flow_item_esp = collections.namedtuple('rte_flow_item_esp', ['hdr'])
rte_flow_item_esp.__new__.__defaults__ = (rte_esp_hdr(),)
# Default mask for RTE_FLOW_ITEM_TYPE_ESP.
rte_flow_item_esp_mask = rte_flow_item_esp(rte_esp_hdr(spi=0xffffffff))

# RTE_FLOW_ITEM_TYPE_GENEVE
rte_flow_item_geneve = collections.namedtuple('rte_flow_item_geneve', ['ver_opt_len_o_c_rsvd0', 'protocol', 'vni', 'rsvd1'])
rte_flow_item_geneve.__new__.__defaults__ = (0, 0, b'', 0)
# Default mask for RTE_FLOW_ITEM_TYPE_GENEVE.
rte_flow_item_geneve_mask = rte_flow_item_geneve(vni=b'\xff\xff\xff')

# RTE_FLOW_ITEM_TYPE_VXLAN_GPE
rte_flow_item_vxlan_gpe = collections.namedtuple('rte_flow_item_vxlan_gpe', ['flags', 'rsvd0', 'protocol', 'vni', 'rsvd1'])
rte_flow_item_vxlan_gpe.__new__.__defaults__ = (0, b'', 0, b'', 0)
# Default mask for RTE_FLOW_ITEM_TYPE_VXLAN_GPE.
rte_flow_item_vxlan_gpe_mask = rte_flow_item_vxlan_gpe(vni=b'\xff\xff\xff')

# RTE_FLOW_ITEM_TYPE_ARP_ETH_IPV4
rte_flow_item_arp_eth_ipv4 = collections.namedtuple('rte_flow_item_arp_eth_ipv4', ['hrd', 'pro', 'hln', 'pln', 'op',
                                                                           'sha', 'spa', 'tha', 'tpa'])
rte_flow_item_arp_eth_ipv4.__new__.__defaults__ = (0, 0, 0, 0, 0, rte_ether_addr(), 0, rte_ether_addr(), 0)
# Default mask for RTE_FLOW_ITEM_TYPE_ARP_ETH_IPV4.
rte_flow_item_arp_eth_ipv4_mask = rte_flow_item_arp_eth_ipv4(sha=rte_ether_addr(b'\xff\xff\xff\xff\xff\xff'),
                                                     spa=0xffffffff,
                                                     tha=rte_ether_addr(b'\xff\xff\xff\xff\xff\xff'),
                                                     tpa=0xffffffff)

# RTE_FLOW_ITEM_TYPE_IPV6_EXT
rte_flow_item_ipv6_ext = collections.namedtuple('rte_flow_item_ipv6_ext', ['next_hdr'])
rte_flow_item_ipv6_ext.__new__.__defaults__ = (0,)
# Default mask for RTE_FLOW_ITEM_TYPE_IPV6_EXT.
rte_flow_item_ipv6_ext_mask = rte_flow_item_ipv6_ext(next_hdr=0xff)

# RTE_FLOW_ITEM_TYPE_ICMP6
rte_flow_item_icmp6 = collections.namedtuple('rte_flow_item_icmp6', ['type_', 'code', 'checksum'])
rte_flow_item_icmp6.__new__.__defaults__ = (0, 0, 0)
# Default mask for RTE_FLOW_ITEM_TYPE_ICMP6.
rte_flow_item_icmp6_mask = rte_flow_item_icmp6(type_=0xff, code=0xff)

# RTE_FLOW_ITEM_TYPE_ICMP6_ND_NS
rte_flow_item_icmp6_nd_ns = collections.namedtuple('rte_flow_item_icmp6_nd_ns', ['type_', 'code', 'checksum', 'reserved', 'target_addr'])
rte_flow_item_icmp6_nd_ns.__new__.__defaults__ = (0, 0, 0, 0, b'')
# Default mask for RTE_FLOW_ITEM_TYPE_ICMP6_ND_NS.
rte_flow_item_icmp6_nd_ns_mask = rte_flow_item_icmp6_nd_ns(target_addr=b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')

# RTE_FLOW_ITEM_TYPE_ICMP6_ND_NA
rte_flow_item_icmp6_nd_na = collections.namedtuple('rte_flow_item_icmp6_nd_na', ['type_', 'code', 'checksum', 'rso_reserved', 'target_addr'])
rte_flow_item_icmp6_nd_na.__new__.__defaults__ = (0, 0, 0, 0, b'')
# Default mask for RTE_FLOW_ITEM_TYPE_ICMP6_ND_NA.
rte_flow_item_icmp6_nd_na_mask = rte_flow_item_icmp6_nd_na(target_addr=b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')

# RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT
rte_flow_item_icmp6_nd_opt = collections.namedtuple('rte_flow_item_icmp6_nd_opt', ['type_', 'length'])
rte_flow_item_icmp6_nd_opt.__new__.__defaults__ = (0, 0)
# Default mask for RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT.
rte_flow_item_icmp6_nd_opt_mask = rte_flow_item_icmp6_nd_opt(type_=0xff)

# RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_SLA_ETH
rte_flow_item_icmp6_nd_opt_sla_eth = collections.namedtuple('rte_flow_item_icmp6_nd_opt_sla_eth', ['type_', 'length', 'sla'])
rte_flow_item_icmp6_nd_opt_sla_eth.__new__.__defaults__ = (0, 0, rte_ether_addr())
# Default mask for RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_SLA_ETH.
rte_flow_item_icmp6_nd_opt_sla_eth_mask = rte_flow_item_icmp6_nd_opt_sla_eth(sla=rte_ether_addr(addr_bytes=b'\xff\xff\xff\xff\xff\xff'))

# RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_TLA_ETH
rte_flow_item_icmp6_nd_opt_tla_eth = collections.namedtuple('rte_flow_item_icmp6_nd_opt_tla_eth', ['type_', 'length', 'tla'])
rte_flow_item_icmp6_nd_opt_tla_eth.__new__.__defaults__ = (0, 0, rte_ether_addr())
# Default mask for RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_TLA_ETH.
rte_flow_item_icmp6_nd_opt_tla_eth_mask = rte_flow_item_icmp6_nd_opt_tla_eth(tla=rte_ether_addr(addr_bytes=b'\xff\xff\xff\xff\xff\xff'))

# RTE_FLOW_ITEM_TYPE_MARK
rte_flow_item_mark = collections.namedtuple('rte_flow_item_mark', ['id'])
rte_flow_item_mark.__new__.__defaults__ = (0,)
# Default mask for RTE_FLOW_ITEM_TYPE_MARK.
rte_flow_item_mark_mask = rte_flow_item_mark(id=0xffffffff)

# RTE_FLOW_ITEM_TYPE_META
rte_flow_item_meta = collections.namedtuple('rte_flow_item_meta', ['data'])
rte_flow_item_meta.__new__.__defaults__ = (0,)
# Default mask for RTE_FLOW_ITEM_TYPE_META.
rte_flow_item_meta_mask = rte_flow_item_meta(data=UINT32_MAX)

# RTE_FLOW_ITEM_TYPE_GTP_PSC.
rte_flow_item_gtp_psc = collections.namedtuple('rte_flow_item_gtp_psc', ['pdu_type', 'qfi'])
rte_flow_item_gtp_psc.__new__.__defaults__ = (0, 0)
# Default mask for RTE_FLOW_ITEM_TYPE_GTP_PSC.
rte_flow_item_gtp_psc_mask = rte_flow_item_gtp_psc(qfi=0x3f)

# RTE_FLOW_ITEM_TYPE_PPPOE
rte_flow_item_pppoe = collections.namedtuple('rte_flow_item_pppoe', ['version_type', 'code', 'session_id', 'length'])
rte_flow_item_pppoe.__new__.__defaults__ = (0, 0, 0, 0)

# RTE_FLOW_ITEM_TYPE_PPPOE_PROTO_ID
rte_flow_item_pppoe_proto_id = collections.namedtuple('rte_flow_item_pppoe_proto_id', ['proto_id'])
rte_flow_item_pppoe_proto_id.__new__.__defaults__ = (0,)
# Default mask for RTE_FLOW_ITEM_TYPE_PPPOE_PROTO_ID.
rte_flow_item_pppoe_proto_id_mask = rte_flow_item_pppoe_proto_id(proto_id=0xffff)

# RTE_FLOW_ITEM_TYPE_NSH
rte_flow_item_nsh = collections.namedtuple('rte_flow_item_nsh', ['version', 'oam_pkt', 'reserved', 'ttl', 'length',
                                                         'reserved1', 'mdtype', 'next_proto', 'spi', 'sindex'])
rte_flow_item_nsh.__new__.__defaults__ = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
# Default mask for RTE_FLOW_ITEM_TYPE_NSH.
rte_flow_item_nsh_mask = rte_flow_item_nsh(mdtype=0xf, next_proto=0xff, spi=0xffffff, sindex=0xff)

# RTE_FLOW_ITEM_TYPE_IGMP
rte_flow_item_igmp = collections.namedtuple('rte_flow_item_igmp', ['type_', 'max_resp_time', 'checksum', 'group_addr'])
rte_flow_item_igmp.__new__.__defaults__ = (0, 0, 0, 0)
# Default mask for RTE_FLOW_ITEM_TYPE_IGMP.
rte_flow_item_igmp_mask = rte_flow_item_igmp(group_addr=0xffffffff)

# RTE_FLOW_ITEM_TYPE_AH
rte_flow_item_ah = collections.namedtuple('rte_flow_item_ah', ['next_hdr', 'payload_len', 'reserved', 'spi', 'seq_num'])
rte_flow_item_ah.__new__.__defaults__ = (0, 0, 0, 0, 0)
# Default mask for RTE_FLOW_ITEM_TYPE_AH.
rte_flow_item_ah_mask = rte_flow_item_ah(spi=0xffffffff)

# higig2 frc header.
rte_higig2_frc = collections.namedtuple('rte_higig2_frc', ['ksop', 'tc', 'mcst', 'resv', 'dst_modid', 'dst_pid',
                                                   'src_modid', 'src_pid', 'lbid', 'ppd_type', 'resv1', 'dp'])
rte_higig2_frc.__new__.__defaults__ = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
# higig2 ppt type0 header
rte_higig2_ppt_type0 = collections.namedtuple('rte_higig2_ppt_type0', ['mirror', 'mirror_done', 'mirror_only', 'ingress_tagged',
                                                               'dst_tgid', 'dst_t', 'vc_label2', 'label_present', 'l3',
                                                               'res', 'vc_label1', 'vc_label0', 'vid_high', 'vid_low',
                                                               'opc', 'res1', 'srce_t', 'pf', 'res2', 'hdr_ext_length'])
rte_higig2_ppt_type0.__new__.__defaults__ = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
# higig2 ppt type1 header
rte_higig2_ppt_type1 = collections.namedtuple('rte_higig2_ppt_type1', ['classification', 'resv', 'vid', 'opcode', 'resv1',
                                                               'src_t', 'pfm', 'resv2', 'hdr_ext_len'])
rte_higig2_ppt_type1.__new__.__defaults__ = (0, 0, 0, 0, 0, 0, 0, 0, 0)
# higig2 header
rte_higig2_hdr = collections.namedtuple('rte_higig2_hdr', ['fcr', 'ppt0', 'ppt1'])
rte_higig2_hdr.__new__.__defaults__ = (rte_higig2_frc(), rte_higig2_ppt_type0(), rte_higig2_ppt_type1())
# RTE_FLOW_ITEM_TYPE_HIGIG2
rte_flow_item_higig2_hdr = collections.namedtuple('rte_flow_item_higig2_hdr', ['hdr'])
rte_flow_item_higig2_hdr.__new__.__defaults__ = (rte_higig2_hdr(),)
# Default mask for RTE_FLOW_ITEM_TYPE_HIGIG2.
rte_flow_item_rte_higig2_hdr_mask = rte_flow_item_higig2_hdr(hdr=rte_higig2_hdr(ppt1=rte_higig2_ppt_type1(classification=0xffff, vid=0xfff)))

# RTE_FLOW_ITEM_TYPE_TAG
rte_flow_item_tag = collections.namedtuple('rte_flow_item_tag', ['data', 'index'])
rte_flow_item_tag.__new__.__defaults__ = (0, 0)
# Default mask for RTE_FLOW_ITEM_TYPE_TAG.
rte_flow_item_tag_mask = rte_flow_item_tag(data=0xffffffff, index=0xff)

# RTE_FLOW_ITEM_TYPE_L2TPV3OIP
rte_flow_item_l2tpv3oip = collections.namedtuple('rte_flow_item_l2tpv3oip', ['session_id'])
rte_flow_item_l2tpv3oip.__new__.__defaults__ = (0,)
# Default mask for RTE_FLOW_ITEM_TYPE_L2TPV3OIP.
rte_flow_item_l2tpv3oip_mask = rte_flow_item_l2tpv3oip(session_id=UINT32_MAX)

rte_flow_item = collections.namedtuple('rte_flow_item', ['type_', 'spec', 'last', 'mask'])
rte_flow_item.__new__.__defaults__ = (None, None, None)

@unique
class rte_flow_action_type(Enum):
    RTE_FLOW_ACTION_TYPE_END        = 0
    RTE_FLOW_ACTION_TYPE_VOID       = 1
    RTE_FLOW_ACTION_TYPE_PASSTHRU   = 2
    RTE_FLOW_ACTION_TYPE_JUMP       = 3
    RTE_FLOW_ACTION_TYPE_MARK       = 4
    RTE_FLOW_ACTION_TYPE_FLAG       = 5
    RTE_FLOW_ACTION_TYPE_QUEUE      = 6
    RTE_FLOW_ACTION_TYPE_DROP       = 7
    RTE_FLOW_ACTION_TYPE_COUNT      = 8
    RTE_FLOW_ACTION_TYPE_RSS        = 9
    RTE_FLOW_ACTION_TYPE_PF         = 10
    RTE_FLOW_ACTION_TYPE_VF         = 11
    RTE_FLOW_ACTION_TYPE_PHY_PORT   = 12
    RTE_FLOW_ACTION_TYPE_PORT_ID    = 13
    RTE_FLOW_ACTION_TYPE_METER      = 14
    RTE_FLOW_ACTION_TYPE_SECURITY   = 15
    RTE_FLOW_ACTION_TYPE_OF_SET_MPLS_TTL    = 16
    RTE_FLOW_ACTION_TYPE_OF_DEC_MPLS_TTL    = 17
    RTE_FLOW_ACTION_TYPE_OF_SET_NW_TTL      = 18
    RTE_FLOW_ACTION_TYPE_OF_DEC_NW_TTL      = 19
    RTE_FLOW_ACTION_TYPE_OF_COPY_TTL_OUT    = 20
    RTE_FLOW_ACTION_TYPE_OF_COPY_TTL_IN     = 21
    RTE_FLOW_ACTION_TYPE_OF_POP_VLAN        = 22
    RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN       = 23
    RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID    = 24
    RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP    = 25
    RTE_FLOW_ACTION_TYPE_OF_POP_MPLS    = 26
    RTE_FLOW_ACTION_TYPE_OF_PUSH_MPLS   = 27
    RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP    = 28
    RTE_FLOW_ACTION_TYPE_VXLAN_DECAP    = 29
    RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP    = 30
    RTE_FLOW_ACTION_TYPE_NVGRE_DECAP    = 31
    RTE_FLOW_ACTION_TYPE_RAW_ENCAP      = 32
    RTE_FLOW_ACTION_TYPE_RAW_DECAP      = 33
    RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC   = 34
    RTE_FLOW_ACTION_TYPE_SET_IPV4_DST   = 35
    RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC   = 36
    RTE_FLOW_ACTION_TYPE_SET_IPV6_DST   = 37
    RTE_FLOW_ACTION_TYPE_SET_TP_SRC     = 38
    RTE_FLOW_ACTION_TYPE_SET_TP_DST     = 39
    RTE_FLOW_ACTION_TYPE_MAC_SWAP       = 40
    RTE_FLOW_ACTION_TYPE_DEC_TTL        = 41
    RTE_FLOW_ACTION_TYPE_SET_TTL        = 42
    RTE_FLOW_ACTION_TYPE_SET_MAC_SRC    = 43
    RTE_FLOW_ACTION_TYPE_SET_MAC_DST    = 44
    RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ    = 45
    RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ    = 46
    RTE_FLOW_ACTION_TYPE_INC_TCP_ACK    = 47
    RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK    = 48
    RTE_FLOW_ACTION_TYPE_SET_TAG        = 49
    RTE_FLOW_ACTION_TYPE_SET_META       = 50

# RTE_FLOW_ACTION_TYPE_JUMP
rte_flow_action_jump = collections.namedtuple('rte_flow_action_jump', ['group'])
rte_flow_action_jump.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_MARK
rte_flow_action_mark = collections.namedtuple('rte_flow_action_mark', ['id'])
rte_flow_action_mark.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_QUEUE
rte_flow_action_queue = collections.namedtuple('rte_flow_action_queue', ['index'])
rte_flow_action_queue.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_COUNT
rte_flow_action_count = collections.namedtuple('rte_flow_action_count', ['id'])
rte_flow_action_count.__new__.__defaults__ = (0)

# RTE_FLOW_ACTION_TYPE_COUNT (query)
rte_flow_query_count = collections.namedtuple('rte_flow_query_count', ['reset', 'hits_set', 'bytes_set', 'reserved',
                                                               'hits', 'bytes'])
rte_flow_query_count.__new__.__defaults__ = (0, 0, 0, 0, 0, 0)

# Hash function types.
@unique
class rte_eth_hash_function(Enum):
    RTE_ETH_HASH_FUNCTION_DEFAULT    = 0,
    RTE_ETH_HASH_FUNCTION_TOEPLITZ   = 2, # Toeplitz
    RTE_ETH_HASH_FUNCTION_SIMPLE_XOR =3, # Simple XOR
    RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ = 4,
    RTE_ETH_HASH_FUNCTION_MAX = 5

# RTE_FLOW_ACTION_TYPE_RSS
rte_flow_action_rss = collections.namedtuple('rte_flow_action_rss', ['func', 'level', 'types', 'key_len',
                                                             'queue_num', 'key', 'queue'])
rte_flow_action_rss.__new__.__defaults__ = (0, 0, 0, 0, None, None)

# RTE_FLOW_ACTION_TYPE_VF
rte_flow_action_vf = collections.namedtuple('rte_flow_action_vf', ['reserved', 'original', 'id'])
rte_flow_action_vf.__new__.__defaults__ = (0, 0, 1)

# RTE_FLOW_ITEM_TYPE_PHY_PORT
rte_flow_action_phy_port = collections.namedtuple('rte_flow_action_phy_port', ['original', 'reserved', 'index'])
rte_flow_action_phy_port.__new__.__defaults__ = (0, 0, 1)

# RTE_FLOW_ACTION_TYPE_PORT_ID
rte_flow_action_port_id = collections.namedtuple('rte_flow_action_port_id', ['original', 'reserved', 'id'])
rte_flow_action_port_id.__new__.__defaults__ = (0, 0, 1)

# RTE_FLOW_ACTION_TYPE_METER
rte_flow_action_meter = collections.namedtuple('rte_flow_action_meter', ['mtr_id'])
rte_flow_action_meter.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_SECURITY
rte_flow_action_security = collections.namedtuple('rte_flow_action_security', ['security_session'])
rte_flow_action_security.__new__.__defaults__ = (None,)

# RTE_FLOW_ACTION_TYPE_OF_SET_MPLS_TTL
rte_flow_action_of_set_mpls_ttl = collections.namedtuple('rte_flow_action_of_set_mpls_ttl', ['mpls_ttl'])
rte_flow_action_of_set_mpls_ttl.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_OF_SET_NW_TTL
rte_flow_action_of_set_nw_ttl = collections.namedtuple('rte_flow_action_of_set_nw_ttl', ['nw_ttl'])
rte_flow_action_of_set_nw_ttl.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN
rte_flow_action_of_push_vlan = collections.namedtuple('rte_flow_action_of_push_vlan', ['ethertype'])
rte_flow_action_of_push_vlan.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID
rte_flow_action_of_set_vlan_vid = collections.namedtuple('rte_flow_action_of_set_vlan_vid', ['vlan_vid'])
rte_flow_action_of_set_vlan_vid.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP
rte_flow_action_of_set_vlan_pcp = collections.namedtuple('rte_flow_action_of_set_vlan_pcp', ['vlan_pcp'])
rte_flow_action_of_set_vlan_pcp.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_OF_POP_MPLS
rte_flow_action_of_pop_mpls = collections.namedtuple('rte_flow_action_of_pop_mpls', ['ethertype'])
rte_flow_action_of_pop_mpls.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_OF_PUSH_MPLS
rte_flow_action_of_push_mpls = collections.namedtuple('rte_flow_action_of_push_mpls', ['ethertype'])
rte_flow_action_of_push_mpls.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP
rte_flow_action_vxlan_encap = collections.namedtuple('rte_flow_action_vxlan_encap', ['definition'])

# RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP
rte_flow_action_nvgre_encap = collections.namedtuple('rte_flow_action_nvgre_encap', ['definition'])

# RTE_FLOW_ACTION_TYPE_RAW_ENCAP
rte_flow_action_raw_encap = collections.namedtuple('rte_flow_action_raw_encap', ['data', 'preserve', 'size'])
rte_flow_action_raw_encap.__new__.__defaults__ = (None, None, 0)

# RTE_FLOW_ACTION_TYPE_RAW_DECAP
rte_flow_action_raw_decap = collections.namedtuple('rte_flow_action_raw_decap', ['data', 'size'])
rte_flow_action_raw_decap.__new__.__defaults__ = (None, 0)

# RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC
# RTE_FLOW_ACTION_TYPE_SET_IPV4_DST
rte_flow_action_set_ipv4 = collections.namedtuple('rte_flow_action_set_ipv4', ['ipv4_addr'])
rte_flow_action_set_ipv4.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC
# RTE_FLOW_ACTION_TYPE_SET_IPV6_DST
rte_flow_action_set_ipv6 = collections.namedtuple('rte_flow_action_set_ipv6', ['ipv6_addr'])
rte_flow_action_set_ipv6.__new__.__defaults__ = (b'',)

# RTE_FLOW_ACTION_TYPE_SET_TP_SRC
# RTE_FLOW_ACTION_TYPE_SET_TP_DST
rte_flow_action_set_tp = collections.namedtuple('rte_flow_action_set_tp', ['port'])
rte_flow_action_set_tp.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_SET_TTL
rte_flow_action_set_ttl = collections.namedtuple('rte_flow_action_set_ttl', ['ttl_value'])
rte_flow_action_set_ttl.__new__.__defaults__ = (0,)

# RTE_FLOW_ACTION_TYPE_SET_MAC
rte_flow_action_set_mac = collections.namedtuple('rte_flow_action_set_mac', ['mac_addr'])
rte_flow_action_set_mac.__new__.__defaults__ = (b'',)

# RTE_FLOW_ACTION_TYPE_SET_TAG
rte_flow_action_set_tag = collections.namedtuple('rte_flow_action_set_tag', ['data', 'mask', 'index'])
rte_flow_action_set_tag.__new__.__defaults__ = (0, 0, 0)

# RTE_FLOW_ACTION_TYPE_SET_META
rte_flow_action_set_meta = collections.namedtuple('rte_flow_action_set_meta', ['data', 'mask'])
rte_flow_action_set_meta.__new__.__defaults__ = (0, 0)

# RTE_FLOW_ACTION_TYPE_SET_IPV4_DSCP
# RTE_FLOW_ACTION_TYPE_SET_IPV6_DSCP
rte_flow_action_set_dscp = collections.namedtuple('rte_flow_action_set_dscp', ['dscp'])
rte_flow_action_set_dscp.__new__.__defaults__ = (0,)

rte_flow_action = collections.namedtuple('rte_flow_action', ['type_', 'conf'])
rte_flow_action.__new__.__defaults__ = (None,)

@unique
class rte_rte_flow_error_type(Enum):
    RTE_FLOW_ERROR_TYPE_NONE        = 0
    RTE_FLOW_ERROR_TYPE_UNSPECIFIED = 1
    RTE_FLOW_ERROR_TYPE_HANDLE      = 2
    RTE_FLOW_ERROR_TYPE_ATTR_GROUP  = 3
    RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY=4
    RTE_FLOW_ERROR_TYPE_ATTR_INGRESS= 5
    RTE_FLOW_ERROR_TYPE_ATTR_EGRESS = 6
    RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER=7
    RTE_FLOW_ERROR_TYPE_ATTR        = 8
    RTE_FLOW_ERROR_TYPE_ITEM_NUM    = 9
    RTE_FLOW_ERROR_TYPE_ITEM_SPEC   = 10
    RTE_FLOW_ERROR_TYPE_ITEM_LAST   = 11
    RTE_FLOW_ERROR_TYPE_ITEM_MASK   = 12
    RTE_FLOW_ERROR_TYPE_ITEM        = 13
    RTE_FLOW_ERROR_TYPE_ACTION_NUM  = 14
    RTE_FLOW_ERROR_TYPE_ACTION_CONF = 15
    RTE_FLOW_ERROR_TYPE_ACTION      = 16

# rte_flow_error
rte_flow_error = collections.namedtuple('rte_flow_error', ['type_', 'cause', 'message'])
rte_flow_error.__new__.__defaults__ = (None, None, None)

# RTE_FLOW_CONV_OP_RULE
rte_flow_conv_rule = collections.namedtuple('rte_flow_conv_rule', ['attr_ro', 'attr', 'pattern_ro', 'pattern',
                                                           'actions_ro', 'actions'])
rte_flow_conv_rule.__new__.__defaults__ = (None, None, None, None, None, None)

@unique
class rte_flow_conv_op(Enum):
    RTE_FLOW_CONV_OP_NONE       = 0
    RTE_FLOW_CONV_OP_ATTR       = 1
    RTE_FLOW_CONV_OP_ITEM       = 2
    RTE_FLOW_CONV_OP_ACTION     = 3
    RTE_FLOW_CONV_OP_PATTERN    = 4
    RTE_FLOW_CONV_OP_ACTIONS    = 5
    RTE_FLOW_CONV_OP_RULE       = 6
    RTE_FLOW_CONV_OP_ITEM_NAME  = 7
    RTE_FLOW_CONV_OP_ACTION_NAME= 8
    RTE_FLOW_CONV_OP_ITEM_NAME_PTR=9
    RTE_FLOW_CONV_OP_ACTION_NAME_PTR=10

rte_flow_desc = collections.namedtuple('rte_flow_desc', ['size', 'attr', 'items', 'actions', 'data'])
rte_flow_desc.__new__.__defaults__ = (0, 0, None, None, b'')

rte_flow_attr = collections.namedtuple('rte_flow_attr', ['group', 'priority', 'ingress', 'egress', 'transfer', 'reserved'])
rte_flow_attr.__new__.__defaults__ = (0, 0, 1, 0, 0, 0)

rte_flow_list_result = collections.namedtuple('rte_flow_list_result', ['flow_id', 'description'])
rte_flow_list_result.__new__.__defaults__ = (0, '')
