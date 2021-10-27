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

import time
import dpdk
#from flow_type import *
from comm_struct import *

# use pf
def test_flow_query_init():
    arg_str = "a.out -c 0x6 -n 4 -d /home/mlh/dcf_source/zy_npg_col-poc_dpdk/x86_64-native-linuxapp-gcc/lib/ -w 88:01.0 --file-prefix=count --"
    arg_list = arg_str.split()

    print("do eal query start")
    dpdk.rte_eal_init(arg_list)
    time.sleep(3)

    # attr
    attr = rte_flow_attr()

    # pattern
    pattern_list = []
    pattern_ether = rte_flow_item(rte_flow_item_type.RTE_FLOW_ITEM_TYPE_ETH.value) #9
    pattern_list.append(pattern_ether)
    pattern_ipv4_spec = rte_flow_item_ipv4(rte_ipv4_hdr(dst_addr = 0x1010101)) # 1.1.1.1
    pattern_ipv4_mask = rte_flow_item_ipv4(rte_ipv4_hdr(dst_addr = 0xFFFFFFFF))
    pattern_ipv4  = rte_flow_item(rte_flow_item_type.RTE_FLOW_ITEM_TYPE_IPV4.value, pattern_ipv4_spec, None, pattern_ipv4_mask) #RTE_FLOW_ITEM_TYPE_IPV4
    pattern_list.append(pattern_ipv4)
    pattern_end = rte_flow_item(rte_flow_item_type.RTE_FLOW_ITEM_TYPE_END.value) #0
    pattern_list.append(pattern_end)

    # action
    action_list = []
    action_list.append(rte_flow_action(rte_flow_action_type.RTE_FLOW_ACTION_TYPE_DROP.value)) #7
    action_list.append(rte_flow_action(rte_flow_action_type.RTE_FLOW_ACTION_TYPE_COUNT.value, rte_flow_action_count())) #8
    action_list.append(rte_flow_action(rte_flow_action_type.RTE_FLOW_ACTION_TYPE_END.value)) #0

    dpdk.rte_flow_create(0, attr, pattern_list, action_list)

# use vf0 and keep pf bind to kernel
def test_flow_dcf_init():
    arg_str = "a.out -c 0x30 -n 4 -d /home/mlh/dcf_source/zy_npg_col-poc_dpdk/x86_64-native-linuxapp-gcc/lib/ -w 88:01.0,cap=dcf --file-prefix=dcf --"
    arg_list = arg_str.split()

    print("do eal init dcf start")
    dpdk.rte_eal_init(arg_list)
    time.sleep(3)

    # attr
    attr = rte_flow_attr()

    # pattern
    pattern_list = []
    pattern_ether = rte_flow_item(rte_flow_item_type.RTE_FLOW_ITEM_TYPE_ETH.value) #9
    pattern_list.append(pattern_ether)
    pattern_ipv4_spec = rte_flow_item_ipv4(rte_ipv4_hdr(dst_addr = 0x1010101)) # 1.1.1.1
    pattern_ipv4_mask = rte_flow_item_ipv4(rte_ipv4_hdr(dst_addr = 0xFFFFFFFF))
    pattern_ipv4  = rte_flow_item(rte_flow_item_type.RTE_FLOW_ITEM_TYPE_IPV4.value, pattern_ipv4_spec, None, pattern_ipv4_mask) #RTE_FLOW_ITEM_TYPE_IPV4
    pattern_list.append(pattern_ipv4)
    pattern_end = rte_flow_item(rte_flow_item_type.RTE_FLOW_ITEM_TYPE_END.value) #0
    pattern_list.append(pattern_end)

    # action
    action_list = []
    action_list.append(rte_flow_action(rte_flow_action_type.RTE_FLOW_ACTION_TYPE_VF.value, rte_flow_action_vf(0,0,1))) #11
    action_list.append(rte_flow_action(rte_flow_action_type.RTE_FLOW_ACTION_TYPE_END.value)) #0

    #dpdk.rte_flow_validate(0, attr, pattern_list, action_list)
    dpdk.rte_flow_create(0, attr, pattern_list, action_list)


def __main__():
    #test_flow_query_init()
    test_flow_dcf_init()
    #print("show port list:")
    #dpdk.show_port_list()

    while 1 > 0:
        arg = input("\ncmd: l --list, d --destroy, f --flush,q --query\n")
        if arg == "l":
            print("list all flows:")
            dpdk.rte_flow_list(0)
        elif arg == "d":
            print("destroy port 0 rule 0:")
            dpdk.rte_flow_destroy(0, 0)
        elif arg == "f":
            print("destroy port 0 all rule:")
            dpdk.rte_flow_flush(0)
        elif arg == "q":
            print("query port 0 rule 0:")
            q = dpdk.rte_flow_query(0, 0)
            if q:
                print("Port 0 flow_id 0 COUNT")
                print("  hits_set: ", q.hits_set)
                print("  bytes_set: ", q.bytes_set)
                print("  hits: ", q.hits)
                print("  bytes: ", q.bytes)

__main__()
