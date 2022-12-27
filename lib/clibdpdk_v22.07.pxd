import cython
from libc.stdint cimport uint32_t, int32_t, int64_t, uint8_t, uint16_t, uint64_t

cdef extern from "rte_flow.h" nogil:
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

    struct rte_flow_item_vf:
        uint32_t id

    struct rte_flow_item_phy_port:
        uint32_t index

    struct rte_flow_item_port_id:
        uint32_t id

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