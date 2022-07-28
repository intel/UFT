#! /usr/bin/python3
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

import sys
sys.path.append("./rpc")
sys.path.append("./lib")
import grpc
from flow_pb2 import *
from flow_pb2_grpc import FlowServiceStub
from qos_pb2 import *
from qos_pb2_grpc import QosServiceStub
import sys

connect_port = 50051

def create_flow(mode='normal',port_id=0):
    req = RequestFlowCreate()
    req.port_id = port_id
    # attr
    #at = FlowAttr(group=0,priority=0,ingress=1,egress=0,transfer=0)
    req.attr.ingress=1

    # pattend
    patten1 = rte_flow_item()
    patten1.type=9#rte_flow_itemType.RTE_FLOW_ITEM_TYPE_ETH.value
    addr_t = rte_ether_addr()
    # 11:11:11:11:11:11
    addr_t.addr_bytes=b'\x11\x11\x11\x11\x11\x11'
    addr_s = rte_ether_addr()
    # 12:12:11:11:11:11
    addr_s.addr_bytes=b'\x12\x12\x11\x11\x11\x11'
    #spec = rte_flow_item_eth(dst=addr_t, src=addr_s)
    #patten1.spec.Pack(spec)
    req.pattern.append(patten1)

    patten2 = rte_flow_item()
    patten2.type=11 # RTE_FLOW_ITEM_TYPE_IPV4
    spec=rte_flow_item_ipv4(hdr=rte_ipv4_hdr(dst_addr=0x1010101))
    patten2.spec.Pack(spec)
    mask=rte_flow_item_ipv4(hdr=rte_ipv4_hdr(dst_addr=0xFFFFFFFF))
    patten2.mask.Pack(mask)
    req.pattern.append(patten2)

    patten3 = rte_flow_item()
    patten3.type = 14  # RTE_FLOW_ITEM_TYPE_UDP
    spec = rte_flow_item_udp(hdr=rte_udp_hdr(src_port=0xBB8, dst_port=0xBB9))
    patten3.spec.Pack(spec)
    req.pattern.append(patten3)

    patten_end = rte_flow_item()
    patten_end.type=0 #RTE_FLOW_ITEM_TYPE_END
    req.pattern.append(patten_end)

    if mode=='normal':
        # action
        action = rte_flow_action()
        action.type = 11 #RTE_FLOW_ACTION_TYPE_VF
        vf_action = rte_flow_action_vf(reserved=0,original=0,id=1)
        action.conf.Pack(vf_action)

        req.action.append(action)

        action = rte_flow_action()
        action.type=0 # RTE_FLOW_ACTION_TYPE_END
        req.action.append(action)
    else:
        action = rte_flow_action()
        action.type = 7 # RTE_FLOW_ACTION_TYPE_DROP
        req.action.append(action)

        action = rte_flow_action()
        action.type = 8 # RTE_FLOW_ACTION_TYPE_COUNT
        count_action = rte_flow_action_count()
        action.conf.Pack(count_action)
        req.action.append(action)

        action = rte_flow_action()
        action.type=0 # RTE_FLOW_ACTION_TYPE_END
        req.action.append(action)

    return req

def test_validate(port_id):
    req = create_flow(mode='normal', port_id=port_id)
    resp = stub.Validate(req)
    print(resp)

def test_create(port_id):
    req = create_flow(mode='normal',port_id=port_id)
    resp=stub.Create(req)
    print(resp)

def test_destroy(port_id):
    req = RequestFlowofPort()
    req.port_id = port_id
    req.flow_id = 0
    resp = stub.Destroy(req)
    print(resp)

def test_flush(port_id):
    req = RequestofPort()
    req.port_id = port_id
    resp = stub.Flush(req)
    print(resp)

def test_query(port_id):
    req = create_flow(mode='query', port_id=port_id)
    resp=stub.Create(req)
    print (resp)
    print('rule create over')

    # query request
    req = RequestFlowofPort()
    req.port_id = port_id
    req.flow_id = 0
    resp = stub.Query(req)
    print(resp.data)
    print(resp.error_info)

def test_list(port_id):
    req = RequestofPort()
    req.port_id = port_id
    resp = stub.List(req)
    print(resp)

def test_isolate(port_id):
    req = RequestIsolate()
    req.port_id = port_id
    req.isolated_mode = 0
    resp = stub.Isolate(req)
    print(resp)

def test_list_ports():
    req = RequestListPorts()
    resp = stub.ListPorts(req)
    print(resp)


###QoS####

def test_add_sched_tree(port_id, profile_id, tc_num, vf_num):
    req = RequestAdd_TM_Node()
    req.port_id = port_id
    req.profile_id = profile_id
    req.tc_num = tc_num
    req.vf_num = vf_num

    resp = qos_stub.Add_TM_Node(req)
    print(resp)

def test_set_node_bw(port_id, profile_id, committed_bw, peak_bw):
    req = RequestSet_Node_BW()
    req.port_id = port_id
    req.profile_id = profile_id
    req.committed_bw = committed_bw
    req.peak_bw = peak_bw

    resp = qos_stub.Set_Node_BW(req)
    print(resp)

def test_del_node_bw(port_id, profile_id):
    req = RequestDel_Node_BW()
    req.port_id = port_id
    req.profile_id = profile_id

    resp = qos_stub.Del_Node_BW(req)
    print(resp)

def test_get_node_bw(port_id):
    req = RequestGet_Node_BW()
    req.port_id = port_id

    resp = qos_stub.Get_Node_BW(req)
    print(resp)


if __name__ == '__main__':

    if len(sys.argv) <= 1:
        raise Exception('please input you action: create, list, destroy,'
                        ' query, flush, validate, listports,'
                        ' add_sched_tree, set_node_bw, del_node_bw, get_node_bw')

    if sys.argv[1] in ['create', 'list', 'destroy', 'flush', 'validate', 'query'
                       ]:
        if len(sys.argv) <= 2:
            raise Exception('please input port id')
        port_id = int(sys.argv[2])

    elif sys.argv[1] == 'add_sched_tree':
        if len(sys.argv) != 6:
            raise Exception('add_port_node port_id profile_id tc_num vf_num')
        port_id = int(sys.argv[2])
        profile_id = int(sys.argv[3])
        tc_num = int(sys.argv[4])
        vf_num = int(sys.argv[5])

    elif sys.argv[1] == 'set_node_bw':
        if len(sys.argv) != 6:
            raise Exception('set_node_bw port_id profile_id committed_bw peak_bw')
        port_id = int(sys.argv[2])
        profile_id = int(sys.argv[3])
        committed_bw = int(sys.argv[4])
        peak_bw = int(sys.argv[5])

    elif sys.argv[1] == 'del_node_bw':
        if len(sys.argv) != 4:
            raise Exception('del_node_bw port_id profile_id')
        port_id = int(sys.argv[2])
        profile_id = int(sys.argv[3])

    elif sys.argv[1] == 'get_node_bw':
        if len(sys.argv) != 3:
            raise Exception('get_node_bw port_id')
        port_id = int(sys.argv[2])

    elif sys.argv[1] != 'listports':
        raise Exception('please input right action: create, list, destroy, query, flush, validate, listports')

    with open('./my_certs/ca.cert', 'rb') as f:
        creds = grpc.ssl_channel_credentials(f.read())

    channel = grpc.secure_channel('localhost:50051', creds)
    stub = FlowServiceStub(channel)
    qos_stub = QosServiceStub(channel)
    if sys.argv[1].lower() == 'create':
        test_create(port_id)
    elif sys.argv[1].lower() == 'destroy':
        test_destroy(port_id)
    elif sys.argv[1].lower() == 'list':
        test_list(port_id)
    elif sys.argv[1].lower() == 'query':
        test_query(port_id)
    elif sys.argv[1].lower() == 'validate':
        test_validate(port_id)
    elif sys.argv[1].lower() == 'flush':
        test_flush(port_id)
    elif sys.argv[1].lower() == 'listports':
        test_list_ports()
    elif sys.argv[1].lower() == 'add_sched_tree':
        test_add_sched_tree(port_id, profile_id, tc_num, vf_num)
    elif sys.argv[1].lower() == 'set_node_bw':
        test_set_node_bw(port_id, profile_id, committed_bw, peak_bw)
    elif sys.argv[1].lower() == 'del_node_bw':
        test_del_node_bw(port_id, profile_id)
    elif sys.argv[1].lower() == 'get_node_bw':
        test_get_node_bw(port_id)
