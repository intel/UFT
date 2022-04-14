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

cimport cython
from libc.stdint cimport uint32_t, int32_t, int64_t, uint8_t, uint16_t, uint64_t
from libc.errno cimport EAGAIN

DEF RTE_ETHER_ADDR_LEN = 6

IF DPDK_VERSION == "v21.08":
    cdef extern from "rte_flow.h" nogil:
        struct rte_flow_action_count:
            uint32_t shared
            uint32_t reserved
            uint32_t id
ELSE:
    cdef extern from "rte_flow.h" nogil:
        struct rte_flow_action_count:
            uint32_t id

cdef extern from "rte_ether.h" nogil:
    struct rte_ether_addr:
        uint8_t addr_bytes[RTE_ETHER_ADDR_LEN]

cdef extern from "rte_ip.h" nogil:
    struct rte_ipv4_hdr:
        uint8_t  version_ihl
        uint8_t  type_of_service
        uint16_t total_length
        uint16_t packet_id
        uint16_t fragment_offset
        uint8_t  time_to_live
        uint8_t  next_proto_id
        uint16_t hdr_checksum
        uint32_t src_addr
        uint32_t dst_addr

    struct rte_ipv6_hdr:
        uint32_t vtc_flow
        uint16_t payload_len
        uint8_t  proto
        uint8_t  hop_limits
        uint8_t  src_addr[16]
        uint8_t  dst_addr[16]

cdef extern from "rte_icmp.h" nogil:
    struct rte_icmp_hdr:
        uint8_t  icmp_type
        uint8_t  icmp_code
        uint16_t icmp_cksum
        uint16_t icmp_ident
        uint16_t icmp_seq_nb

cdef extern from "rte_udp.h" nogil:
    struct rte_udp_hdr:
        uint16_t src_port
        uint16_t dst_port
        uint16_t dgram_len
        uint16_t dgram_cksum

cdef extern from "rte_tcp.h" nogil:
    struct rte_tcp_hdr:
        uint16_t src_port
        uint16_t dst_port
        uint32_t sent_seq
        uint32_t recv_ack
        uint8_t  data_off
        uint8_t  tcp_flags
        uint16_t rx_win
        uint16_t cksum
        uint16_t tcp_urp

cdef extern from "rte_sctp.h" nogil:
    struct rte_sctp_hdr:
        uint16_t src_port
        uint16_t dst_port
        uint32_t tag
        uint32_t cksum

cdef extern from "rte_esp.h" nogil:
    struct rte_esp_hdr:
        uint32_t spi
        uint32_t seq


# rte eal api
cdef extern from "rte_eal.h" nogil:
    int rte_eal_init(int argc, char *argv[])

# rte flow api
cdef extern from "rte_flow.h" nogil:
    struct rte_flow_attr:
        uint32_t group
        uint32_t priority
        uint32_t ingress
        uint32_t egress
        uint32_t transfer
        uint32_t reserved

    # pattern related as below
    enum rte_flow_item_type:
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

    struct rte_flow_item:
        rte_flow_item_type type
        void    *spec
        void    *last
        void    *mask

    struct rte_flow_item_any:
        uint32_t num

    struct rte_flow_item_vf:
        uint32_t id

    struct rte_flow_item_phy_port:
        uint32_t index

    struct rte_flow_item_port_id:
        uint32_t id

    # TODO convert pattern
    struct rte_flow_item_raw:
        uint32_t relative
        uint32_t search
        uint32_t reserved
        int32_t offset
        uint16_t limit
        uint16_t length
        const uint8_t *pattern # Byte string to look for

    struct rte_flow_item_eth:
        rte_ether_addr dst
        rte_ether_addr src
        uint16_t type

    struct rte_flow_item_vlan:
        uint16_t tci
        uint16_t inner_type

    struct rte_flow_item_ipv4:
        rte_ipv4_hdr    hdr

    struct rte_flow_item_ipv6:
        rte_ipv6_hdr hdr

    struct rte_flow_item_icmp:
        rte_icmp_hdr hdr

    struct rte_flow_item_udp:
        rte_udp_hdr hdr

    struct rte_flow_item_tcp:
        rte_tcp_hdr hdr

    struct rte_flow_item_sctp:
        rte_sctp_hdr hdr

    struct rte_flow_item_vxlan:
        uint8_t flags
        uint8_t rsvd0[3]
        uint8_t vni[3]
        uint8_t rsvd1

    struct rte_flow_item_e_tag:
        uint16_t epcp_edei_in_ecid_b
        uint16_t rsvd_grp_ecid_b
        uint8_t in_ecid_e
        uint8_t ecid_e
        uint16_t inner_type

    struct rte_flow_item_nvgre:
        uint16_t c_k_s_rsvd0_ver
        uint16_t protocol
        uint8_t tni[3]
        uint8_t flow_id

    struct rte_flow_item_mpls:
        uint8_t label_tc_s[3]
        uint8_t ttl

    struct rte_flow_item_gre:
        uint16_t c_rsvd0_ver
        uint16_t protocol

    struct rte_flow_item_fuzzy:
        uint32_t thresh

    struct rte_flow_item_gtp:
        uint8_t v_pt_rsv_flags
        uint8_t msg_type
        uint16_t msg_len
        uint32_t teid

    struct rte_flow_item_esp:
        rte_esp_hdr hdr

    struct rte_flow_item_geneve:
        uint16_t ver_opt_len_o_c_rsvd0
        uint16_t protocol
        uint8_t vni[3]
        uint8_t rsvd1

    struct rte_flow_item_vxlan_gpe:
        uint8_t flags
        uint8_t rsvd0[2]
        uint8_t protocol
        uint8_t vni[3]
        uint8_t rsvd1

    struct rte_flow_item_arp_eth_ipv4:
        uint16_t hrd
        uint16_t pro
        uint8_t hln
        uint8_t pln
        uint16_t op
        rte_ether_addr sha
        uint32_t spa
        rte_ether_addr tha
        uint32_t tpa

    struct rte_flow_item_ipv6_ext:
        uint8_t next_hdr

    struct rte_flow_item_icmp6:
        uint8_t type
        uint8_t code
        uint16_t checksum

    struct rte_flow_item_icmp6_nd_ns:
        uint8_t type
        uint8_t code
        uint16_t checksum
        uint32_t reserved
        uint8_t target_addr[16]

    struct rte_flow_item_icmp6_nd_na:
        uint8_t type
        uint8_t code
        uint16_t checksum
        uint32_t rso_reserved
        uint8_t target_addr[16]

    struct rte_flow_item_icmp6_nd_opt:
        uint8_t type
        uint8_t length

    struct rte_flow_item_icmp6_nd_opt_sla_eth:
        uint8_t type
        uint8_t length
        rte_ether_addr sla

    struct rte_flow_item_icmp6_nd_opt_tla_eth:
        uint8_t type
        uint8_t length
        rte_ether_addr tla

    struct rte_flow_item_meta:
        uint32_t data

    struct rte_flow_item_gtp_psc:
        uint8_t pdu_type
        uint8_t qfi

    struct rte_flow_item_pppoe:
        uint8_t version_type
        uint8_t code
        uint16_t session_id
        uint16_t length

    struct rte_flow_item_pppoe_proto_id:
        uint16_t proto_id

    struct rte_flow_item_tag:
        uint32_t data
        uint8_t index

    struct rte_flow_item_l2tpv3oip:
        uint32_t session_id

    struct rte_flow_item_mark:
        uint32_t id

    struct rte_flow_item_nsh:
        uint32_t version
        uint32_t oam_pkt
        uint32_t reserved
        uint32_t ttl
        uint32_t length
        uint32_t reserved1
        uint32_t mdtype
        uint32_t next_proto
        uint32_t spi
        uint32_t sindex

    struct rte_flow_item_igmp:
        uint32_t type
        uint32_t max_resp_time
        uint32_t checksum
        uint32_t group_addr

    struct rte_flow_item_ah:
        uint32_t next_hdr
        uint32_t payload_len
        uint32_t reserved
        uint32_t spi
        uint32_t seqnum

    # action related as below
    enum rte_flow_action_type:
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

    struct rte_flow_action:
        rte_flow_action_type type
        void    *conf

    struct rte_flow_action_mark:
        uint32_t id

    struct rte_flow_action_jump:
        uint32_t group

    struct rte_flow_action_queue:
        uint16_t index

    struct rte_flow_query_count:
        uint32_t reset
        uint32_t hits_set
        uint32_t bytes_set
        uint32_t reserved
        uint64_t hits
        uint64_t bytes

    enum rte_eth_hash_function:
        RTE_ETH_HASH_FUNCTION_DEFAULT   = 0
        RTE_ETH_HASH_FUNCTION_TOEPLITZ  = 1
        RTE_ETH_HASH_FUNCTION_SIMPLE_XOR= 2
        RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ = 3
        RTE_ETH_HASH_FUNCTION_MAX       = 4

    #TODO rss argument parse
    struct rte_flow_action_rss:
        rte_eth_hash_function func
        uint32_t level
        uint64_t types
        uint32_t key_len
        uint32_t queue_num
        const uint8_t *key
        const uint16_t *queue

    struct rte_flow_action_vf:
        uint32_t reserved
        uint32_t original
        uint32_t id

    struct rte_flow_action_phy_port:
        uint32_t original
        uint32_t reserved
        uint32_t index

    struct rte_flow_action_port_id:
        uint32_t original
        uint32_t reserved
        uint32_t id

    struct rte_flow_action_meter:
        uint32_t mtr_id

    struct rte_flow_action_security:
        void *security_session

    struct rte_flow_action_of_set_mpls_ttl:
        uint8_t mpls_ttl

    struct rte_flow_action_of_set_nw_ttl:
        uint8_t nw_ttl

    struct rte_flow_action_of_push_vlan:
        uint16_t ethertype

    struct rte_flow_action_of_set_vlan_vid:
        uint16_t vlan_vid

    struct rte_flow_action_of_set_vlan_pcp:
        uint8_t vlan_pcp

    struct rte_flow_action_of_pop_mpls:
        uint16_t ethertype

    struct rte_flow_action_of_push_mpls:
        uint16_t ethertype

    struct rte_flow_action_vxlan_encap:
        rte_flow_item *definition

    struct rte_flow_action_nvgre_encap:
        rte_flow_item *definition

    struct rte_flow_action_raw_encap:
        uint8_t *data
        uint8_t *preserve
        size_t size

    struct rte_flow_action_raw_decap:
        uint8_t *data
        size_t size

    struct rte_flow_action_set_ipv4:
        uint32_t ipv4_addr

    struct rte_flow_action_set_ipv6:
        uint8_t ipv6_addr[16]

    struct rte_flow_action_set_tp:
        uint16_t port

    struct rte_flow_action_set_ttl:
        uint8_t ttl_value

    struct rte_flow_action_set_mac:
        uint8_t mac_addr[RTE_ETHER_ADDR_LEN]

    struct rte_flow_action_set_tag:
        uint32_t data
        uint32_t mask
        uint8_t index

    struct rte_flow_action_set_meta:
        uint32_t data
        uint32_t mask

    struct rte_flow_action_set_dscp:
        uint8_t dscp

    enum rte_flow_error_type:
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

    enum rte_flow_conv_op:
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

    struct rte_flow_error:
        rte_flow_error_type type
        void *cause
        char *message

    struct rte_flow_conv_rule:
        const rte_flow_attr *attr_ro
        rte_flow_attr *attr
        const rte_flow_item *pattern_ro
        rte_flow_item *pattern
        const rte_flow_action *actions_ro
        rte_flow_action *actions

    int rte_flow_validate(uint16_t port_id, \
		rte_flow_attr *attr,        \
		rte_flow_item pattern[],    \
		rte_flow_action actions[],  \
		rte_flow_error *error)

    void *rte_flow_create(uint16_t port_id, \
                rte_flow_attr *attr,        \
                rte_flow_item pattern[],     \
                rte_flow_action actions[],   \
                rte_flow_error *error)

    int rte_flow_query(uint16_t port_id,            \
               void *flow, rte_flow_action *action, \
               void *data, rte_flow_error *error)

    int rte_flow_destroy(uint16_t port_id,  \
                 void *flow,            \
                 rte_flow_error *error)

    int rte_flow_conv(rte_flow_conv_op op,      \
              void *dst,                        \
              size_t size,                      \
              void *src,                        \
              rte_flow_error *error)

    void *rte_flow_create(uint16_t port_id, \
                rte_flow_attr *attr,        \
                rte_flow_item pattern[],     \
                rte_flow_action actions[],   \
                rte_flow_error *error)

    int rte_flow_query(uint16_t port_id,            \
               void *flow, rte_flow_action *action, \
               void *data, rte_flow_error *error)

    int rte_flow_destroy(uint16_t port_id,  \
                 void *flow,            \
                 rte_flow_error *error)

    int rte_flow_conv(rte_flow_conv_op op,      \
              void *dst,                        \
              size_t size,                      \
              void *src,                        \
              rte_flow_error *error)

    int rte_flow_flush(uint16_t port_id, \
	          rte_flow_error *error)

    int rte_flow_isolate(uint16_t port_id, \
             int set,                      \
			 rte_flow_error *error)

cdef extern from "rte_ethdev.h":
    uint64_t rte_eth_find_next_owned_by(uint16_t port_id, \
                const uint64_t owner_id)
    int rte_eth_dev_close(uint16_t port_id)

cdef extern from "rte_tm.h":
    struct rte_tm_token_bucket:
        uint64_t rate
        uint64_t size

    struct rte_tm_shaper_params:
        rte_tm_token_bucket committed
        rte_tm_token_bucket peak
        int32_t pkt_length_adjust
        int packet_mode

    enum rte_tm_error_type:
        RTE_TM_ERROR_TYPE_NONE         = 0
        RTE_TM_ERROR_TYPE_UNSPECIFIED  = 1
        RTE_TM_ERROR_TYPE_CAPABILITIES = 2
        RTE_TM_ERROR_TYPE_LEVEL_ID     = 3
        RTE_TM_ERROR_TYPE_WRED_PROFILE = 4
        RTE_TM_ERROR_TYPE_WRED_PROFILE_GREEN  = 5
        RTE_TM_ERROR_TYPE_WRED_PROFILE_YELLOW = 6
        RTE_TM_ERROR_TYPE_WRED_PROFILE_RED    = 7
        RTE_TM_ERROR_TYPE_WRED_PROFILE_ID     = 8
        RTE_TM_ERROR_TYPE_SHARED_WRED_CONTEXT_ID = 9
        RTE_TM_ERROR_TYPE_SHAPER_PROFILE         = 10
        RTE_TM_ERROR_TYPE_SHAPER_PROFILE_COMMITTED_RATE = 11
        RTE_TM_ERROR_TYPE_SHAPER_PROFILE_COMMITTED_SIZE = 12
        RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PEAK_RATE      = 13
        RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PEAK_SIZE      = 14
        RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PKT_ADJUST_LEN = 15
        RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PACKET_MODE    = 16
        RTE_TM_ERROR_TYPE_SHAPER_PROFILE_ID      = 17
        RTE_TM_ERROR_TYPE_SHARED_SHAPER_ID       = 18
        RTE_TM_ERROR_TYPE_NODE_PARENT_NODE_ID    = 19
        RTE_TM_ERROR_TYPE_NODE_PRIORITY          = 20
        RTE_TM_ERROR_TYPE_NODE_WEIGHT            = 21
        RTE_TM_ERROR_TYPE_NODE_PARAMS            = 22
        RTE_TM_ERROR_TYPE_NODE_PARAMS_SHAPER_PROFILE_ID = 23
        RTE_TM_ERROR_TYPE_NODE_PARAMS_SHARED_SHAPER_ID  = 24
        RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SHARED_SHAPERS  = 25
        RTE_TM_ERROR_TYPE_NODE_PARAMS_WFQ_WEIGHT_MODE   = 26
        RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SP_PRIORITIES   = 27
        RTE_TM_ERROR_TYPE_NODE_PARAMS_CMAN              = 28
        RTE_TM_ERROR_TYPE_NODE_PARAMS_WRED_PROFILE_ID   = 29
        RTE_TM_ERROR_TYPE_NODE_PARAMS_SHARED_WRED_CONTEXT_ID = 30
        RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SHARED_WRED_CONTEXTS = 31
        RTE_TM_ERROR_TYPE_NODE_PARAMS_STATS = 32
        RTE_TM_ERROR_TYPE_NODE_ID           = 33

    struct rte_tm_error:
        int type
        const void *cause
        const char *message

    struct rte_nonleaf:
        int *wfq_weight_mode
        uint32_t n_sp_priorities

    struct rte_wred:
        uint32_t wred_profile_id
        uint32_t *shared_wred_context_id
        uint32_t n_shared_wred_contexts

    struct rte_leaf:
        int cman
        rte_wred wred

    struct rte_tm_node_params:
        int32_t shaper_profile_id
        uint32_t *shared_shaper_id
        uint32_t n_shared_shapers
        rte_nonleaf nonleaf
        rte_leaf leaf
        uint64_t stats_mask

    int rte_tm_shaper_profile_add(uint16_t port_id, \
        uint32_t shaper_profile_id,                 \
        rte_tm_shaper_params *profile,              \
        rte_tm_error *error)

    int rte_tm_shaper_profile_delete(uint16_t port_id, \
        uint32_t shaper_profile_id,                    \
        rte_tm_error *error)

    int rte_tm_node_add(uint16_t port_id, \
        uint32_t node_id,                 \
        int32_t parent_node_id,          \
        uint32_t priority,                \
        uint32_t weight,                  \
        uint32_t level_id,                \
        rte_tm_node_params *param,                  \
        rte_tm_error *error)

    int rte_tm_node_delete(uint16_t port_id, \
        uint32_t node_id,                    \
        rte_tm_error *error);

    int rte_tm_hierarchy_commit(uint16_t port_id, \
        int clear_on_fail,                        \
        rte_tm_error *error)

cdef extern from "rte_errno.h":
    int per_lcore__rte_errno

