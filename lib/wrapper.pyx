#! /usr/bin/env python
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
#
from libc.stdlib cimport malloc, free
from libc.string cimport memset, strlen, memcpy
from libc.stdint cimport uint32_t, int32_t, int64_t, uint8_t, uint16_t, uint64_t
from ctypes import *

import time
cimport clibdpdk
import comm_struct
from comm_struct import *

# macro definition
DEF RTE_MAX_ETHPORTS        = 32
DEF RTE_ETH_DEV_NO_OWNER    = 0

# init
def rte_eal_init(args):
    cdef:
        char **c_argv
        int c_ret

    #TODO: Check args type, should be a list of string
    nargs = len(args)
    #TODO: Check length

    c_argv = <char**>malloc(nargs * sizeof(char *))
    if c_argv is NULL:
        raise MemoryError()

    for i in range(nargs):
        #trick line, we need hold the temp varible first
        #otherwise, wrapper.pyx:229:32: Storing unsafe C derivative of temporary Python reference
        args[i] = args[i].encode()
        c_argv[i] = args[i]
        #print(c_argv[i])

    c_ret = clibdpdk.rte_eal_init(nargs, c_argv)
    free(c_argv)

    return c_ret

def rte_eth_dev_close(port_id):
    try:
        clibdpdk.rte_eth_dev_close(port_id)
    except Exception as e:
        print("Except: {}".format(e))
    print("close port %d" %port_id)

# return < 0: error occur and raise error message.
def rte_flow_validate(port_id, attr, patterns, actions):
    cdef:
        clibdpdk.rte_flow_attr *c_attr
        clibdpdk.rte_flow_item *c_patterns
        clibdpdk.rte_flow_action *c_actions

        clibdpdk.rte_flow_error c_error
        int c_ret

    c_attr = <clibdpdk.rte_flow_attr*>py2c_convert(attr, mapping)
    c_patterns = <clibdpdk.rte_flow_item*>py2c_convert(patterns, mapping)
    c_actions = <clibdpdk.rte_flow_action*>py2c_convert(actions, mapping)

    memset(&c_error, 0x22, sizeof(c_error))
    c_ret = clibdpdk.rte_flow_validate(port_id, c_attr, c_patterns, c_actions, &c_error)
    if c_ret < 0:
       raise Exception(c_error.message)

    print("Validate ok...")
    return 0

# return < 0: error occur, else return flow index on port @port_id.
def rte_flow_create(port_id, attr, patterns, actions):
    cdef:
        clibdpdk.rte_flow_attr *c_attr
        clibdpdk.rte_flow_item *c_patterns
        clibdpdk.rte_flow_action *c_actions

        clibdpdk.rte_flow_error c_error
        void *c_rte_flow
        int c_ret
        char *c_flow_str

    c_attr = <clibdpdk.rte_flow_attr*>py2c_convert(attr, mapping)
    c_patterns = <clibdpdk.rte_flow_item*>py2c_convert(patterns, mapping)
    c_actions = <clibdpdk.rte_flow_action*>py2c_convert(actions, mapping)

    for i in retry_policy.get_limit():
        memset(&c_error, 0x22, sizeof(c_error))
        c_rte_flow = clibdpdk.rte_flow_create(port_id, c_attr, c_patterns, c_actions, &c_error)
        if not (c_rte_flow is NULL and retry_policy.can_retry()):
            break

    if c_rte_flow is NULL:
        raise Exception(c_error.message)

    try:
        c_flow_str = flow_to_string(c_attr, c_patterns, c_actions)
        #print("create get flow string ok:", str(c_flow_str))

    except Exception as e:
        print("Except: {}".format(e))
        clibdpdk.rte_flow_destroy(port_id, c_rte_flow, &c_error)
        py2c_free(c_attr, attr, mapping)
        py2c_free(c_patterns, patterns, mapping)
        py2c_free(c_actions, actions, mapping)
        raise e

    # free args
    py2c_free(c_attr, attr, mapping)
    py2c_free(c_patterns, patterns, mapping)
    py2c_free(c_actions, actions, mapping)

    pyFlow = PyFlow.from_c_rte_flow(c_rte_flow, c_flow_str)
    flow_id = flow_pool.append_flow(port_id, pyFlow)
    print("Flow rule #%d created on port %d" %(flow_id, port_id))

    return flow_id

def rte_flow_list(port_id):
    cdef:
        PyFlow pyFlow

    try:
        pyFlows = flow_pool.get_flows(port_id)

    except Exception as e:
        print("Except: {}".format(e))
        raise e

    flow_list = []
    print("ID\tGroup\tPrio\tAttr\tRule\n")
    for i in range(len(pyFlows)):
        pyFlow = pyFlows[i]
        if not pyFlow is None:
            flow_str = bytes.decode(pyFlow.get_flow_string())
            flow = rte_flow_list_result(i, flow_str)
            flow_list.append(flow)

    return flow_list

# Return -1: error occur, 0: success
# Note: testpmd destroy API provide delete multiple flow once
def rte_flow_destroy(port_id, flow_id):
    cdef:
        clibdpdk.rte_flow_error c_error
        int c_ret
        void *c_rte_flow
        PyFlow pyFlow

    try:
        pyFlow = flow_pool.get_flow(port_id, flow_id)
        c_rte_flow = pyFlow.get_ptr_rte_flow()

    except Exception as e:
        print("Except: {}".format(e))
        raise e

    for i in retry_policy.get_limit():
        c_ret = clibdpdk.rte_flow_destroy(port_id, c_rte_flow, &c_error)
        if c_ret == 0 or not retry_policy.can_retry():
            break

    if c_ret != 0:
        raise Exception("Destroy port %d rule %d fail: %s!" %(port_id, flow_id, c_error.message))

    flow_pool.remove_flow(port_id, flow_id)
    print("Flow rule port %d #%d destroyed" %(port_id, flow_id))

    return 0

def rte_flow_query(port_id, flow_id, actions):
    cdef:
        clibdpdk.rte_flow_error c_error
        clibdpdk.rte_flow_action *c_actions
        clibdpdk.rte_flow_query_count  c_count
        int c_ret
        void *c_rte_flow
        PyFlow pyFlow

    try:
        c_actions = <clibdpdk.rte_flow_action *>py2c_convert(actions, mapping)
        pyFlow = flow_pool.get_flow(port_id, flow_id)
        #print("query pyFlow: ", pyFlow, "dir: ", dir(pyFlow))
        c_rte_flow = pyFlow.get_ptr_rte_flow()

    except Exception as e:
        raise Exception("Except: {}".format(e))

    c_ret = clibdpdk.rte_flow_query(port_id, c_rte_flow, c_actions, &c_count, &c_error)
    if c_ret != 0:
        #print("ret: %d, msg: %s" %(c_ret, c_error.message))
        raise Exception("Query flow_id %d fail!(%s)" %(flow_id, c_error.message))

    py2c_free(c_actions, actions, mapping)
    return rte_flow_query_count(c_count.reset, c_count.hits_set, c_count.bytes_set, c_count.reserved, c_count.hits, c_count.bytes)

def rte_eth_find_next_owned_by(port_id, owner):
    port_id = clibdpdk.rte_eth_find_next_owned_by(port_id, owner)
    return port_id

def rte_flow_flush(port_id):
    cdef:
        clibdpdk.rte_flow_error c_error
        int c_ret

    if flow_pool.is_empty() == True:
        return 0

    for i in retry_policy.get_limit():
        c_ret = clibdpdk.rte_flow_flush(port_id, &c_error)
        if c_ret == 0 or not retry_policy.can_retry():
            break

    if c_ret != 0:
        raise Exception("Destroy port %d all rule fail: %s!" %(port_id, c_error.message))

    flow_cnt = flow_pool.get_flow_cnt(port_id)
    for flow_id in range(flow_cnt):
        try:
            flow_pool.remove_flow(port_id, flow_id)
            print("Flow rule port %d #%d destroyed" %(port_id, flow_id))
        except Exception as e:
            print("Flow rule port %d #%d has been removed by Destroy, skip" %(port_id, flow_id))

    flow_pool.reset_flows(port_id)

    return 0

def rte_flow_isolate(port_id, set):
    cdef:
        clibdpdk.rte_flow_error c_error
        int c_ret

    c_ret = clibdpdk.rte_flow_isolate(port_id, set, &c_error)
    if c_ret != 0:
        raise Exception("Flow isolate %d fail: %s!" %(port_id, c_error.message))

    return 0

def rte_tm_shaper_profile_add(port_id, profile_id, commit_bw, peak_bw):
    cdef:
        clibdpdk.rte_tm_shaper_params params
        clibdpdk.rte_tm_error err

    memset(&params, 0, sizeof(params))
    memset(&err, 0, sizeof(err))  #__rte_unused
    params.committed.rate = commit_bw
    params.peak.rate = peak_bw
    ret = clibdpdk.rte_tm_shaper_profile_add(port_id, profile_id, &params, &err)
    if ret != 0:
        raise QosError(ret, "QoS profile add fail")
    return ret

def rte_tm_shaper_profile_delete(port_id, profile_id):
    cdef:
        clibdpdk.rte_tm_error err

    memset(&err, 0, sizeof(err))
    ret = clibdpdk.rte_tm_shaper_profile_delete(port_id, profile_id, &err)
    if ret != 0:
        print("rte_tm_shaper_profile_delete fail ret = %d" % ret)
    return ret

def rte_tm_node_add(port_id, node_id, parent_node_id, level_id, profile_id):
    cdef:
        uint32_t buf[16]
        clibdpdk.rte_tm_error err
        clibdpdk.rte_tm_node_params params

    memset(&params, 0, sizeof(params))
    params.shaper_profile_id = profile_id
    if node_id < 8: #max queue num
        params.leaf.wred.wred_profile_id = 0xffffffff
    else:
        params.nonleaf.n_sp_priorities = 1

    memset(&err, 0, sizeof(err))
    print("node id %s, parent node id %s, profile %s" % (node_id, parent_node_id, profile_id))
    ret = clibdpdk.rte_tm_node_add(port_id, node_id, parent_node_id, 0, 1, level_id, &params, &err)
    if ret != 0:
        raise QosError(ret, "QoS node add faile")
    return ret

def rte_tm_node_delete(port_id, node_id):
    cdef:
        clibdpdk.rte_tm_error err

    memset(&err, 0, sizeof(err))
    ret = clibdpdk.rte_tm_node_delete(port_id, node_id, &err)
    if ret != 0:
        print("rte_tm_node_delete fail ret = %d" % ret)
    return ret

def rte_tm_hierarchy_commit(port_id):
    cdef:
        clibdpdk.rte_tm_error err

    memset(&err, 0, sizeof(err))
    ret = clibdpdk.rte_tm_hierarchy_commit(port_id, 1, &err)
    if ret != 0:
        raise QosError(ret, "sched tree commit fail")
    return ret

def rte_le_to_be_16(val):
    return ((val >> 8) & 0xff) | ((val << 8) & 0xff00)

def rte_le_to_be_32(val):
    return ((val >> 24) & 0xff) | ((val >> 8) & 0xff00) | ((val << 8) & 0xff0000) | ((val << 24) & 0xff000000)

####### Private ########
mapping = {
    "rte_flow_attr": Py2CFlowAttrConvertor(),
    "list_rte_flow_item": Py2CListFlowItemConvertor(),
    "rte_flow_item": Py2CFlowItemConvertor(),
    "rte_flow_item_eth": Py2CFlowItemEthConvertor(),
    "rte_flow_item_ipv4": Py2CFlowItemIPV4Convertor(),
    "rte_flow_item_udp": Py2CFlowItemUDPConvertor(),
    "rte_flow_item_vlan": Py2CFlowItemVLANConvertor(),
    "rte_flow_item_pppoe": Py2CFlowItemPPPOEConvertor(),
    "rte_flow_item_pppoe_proto_id": Py2CFlowItemPPPOE_PROTO_IDConvertor(),
    "list_rte_flow_action": Py2CListFlowActionConvertor(),
    "rte_flow_action": Py2CFlowActionConvertor(),
    "rte_flow_action_count": Py2CFlowActionCountConvertor(),
    "rte_flow_action_vf": Py2CFlowActionVfConvertor(),
}

#Abstract Class for Py2C convertor
cdef class Py2CConvertor:
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        pass

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        pass

cdef class Py2CFlowAttrConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef clibdpdk.rte_flow_attr *c_attr
        print(pyObj)
        c_attr = <clibdpdk.rte_flow_attr*>malloc(sizeof(clibdpdk.rte_flow_attr))
        c_attr.group = pyObj.group
        c_attr.priority = pyObj.priority
        c_attr.ingress = pyObj.ingress
        c_attr.egress = pyObj.egress
        c_attr.transfer = pyObj.transfer
        c_attr.reserved = 0

        print(c_attr.ingress)
        return <void*>c_attr

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        print("free attr")
        free(c_obj)

cdef class Py2CFlowItemConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef clibdpdk.rte_flow_item *c_flow_item
        #print(pyObj)
        if reserved == NULL:
            #print("Low layer malloc memory")
            c_flow_item = <clibdpdk.rte_flow_item*>malloc(sizeof(clibdpdk.rte_flow_item))
            if c_flow_item == NULL:
                raise MemoryError("No free memory");
            memset(c_flow_item, 0, sizeof(clibdpdk.rte_flow_item))
        else:
            #print("Up layer malloc memory")
            c_flow_item = <clibdpdk.rte_flow_item*>reserved
        c_flow_item.type = pyObj.type_
        if not pyObj.spec is None:
            c_flow_item.spec = py2c_convert(pyObj.spec, convert_dict)

        if not pyObj.last is None:
            c_flow_item.last = py2c_convert(pyObj.last, convert_dict)

        if not pyObj.mask is None:
            c_flow_item.mask = py2c_convert(pyObj.mask, convert_dict)

        #print("Use item memory: ", <long>reserved)
        return c_flow_item

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        cdef clibdpdk.rte_flow_item *c_flow_item = <clibdpdk.rte_flow_item *>c_obj
        #print(pyObj)

        if not pyObj.spec is None:
            py2c_free(c_flow_item.spec, pyObj.spec, convert_dict)

        if not pyObj.last is None:
            py2c_free(c_flow_item.last, pyObj.last, convert_dict)

        if not pyObj.mask is None:
            py2c_free(c_flow_item.mask, pyObj.mask, convert_dict)

        if reserved == NULL:
            print("free item: ", pyObj.type_)
            free(c_obj)


cdef class Py2CListFlowItemConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef:
            clibdpdk.rte_flow_item *c_patterns

        # TODO: check patterns is list
        #
        if pyObj[-1].type_ != clibdpdk.RTE_FLOW_ITEM_TYPE_END:
            return NULL

        c_patterns = <clibdpdk.rte_flow_item *>malloc(sizeof(clibdpdk.rte_flow_item) * len(pyObj))
        if c_patterns == NULL:
            raise MemoryError("No free memory");

        memset(<void*>c_patterns, 0, sizeof(clibdpdk.rte_flow_item) * len(pyObj))

        #print("malloc item: ", <long>c_patterns)
        i = 0
        for p in pyObj:
            #print("pattern i %d, type %d" %(i, patterns[i].flow_item_type))
            py2c_convert(p, convert_dict, &c_patterns[i])
            i = i + 1

        return <void*>c_patterns

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        cdef clibdpdk.rte_flow_item *c_patterns = <clibdpdk.rte_flow_item *>c_obj
        i = 0
        for p in pyObj:
            #print("pattern i %d, type %d" %(i, patterns[i].flow_item_type))
            py2c_free(<void*>&c_patterns[i], p, convert_dict, &c_patterns[i])
            i = i + 1

        print("free list item")
        free(c_obj)


cdef class Py2CFlowItemEthConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef clibdpdk.rte_flow_item_eth *c_flow_eth
        print(pyObj)
        if pyObj is None:
            return NULL

        c_flow_eth = <clibdpdk.rte_flow_item_eth *>malloc(sizeof(clibdpdk.rte_flow_item_eth))
        if not c_flow_eth:
            MemoryError("No free memory")
        memset(<void*>c_flow_eth, 0, sizeof(clibdpdk.rte_flow_item_eth))

        for i in range(len(pyObj.dst.addr_bytes)):
            c_flow_eth.dst.addr_bytes[i] = pyObj.dst.addr_bytes[i]
        for i in range(len(pyObj.src.addr_bytes)):
            c_flow_eth.src.addr_bytes[i] = pyObj.src.addr_bytes[i]
        c_flow_eth.type = rte_le_to_be_16(pyObj.type_)
        print("Finish ether:", c_flow_eth[0])
        return <void*>c_flow_eth

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        if reserved == NULL:
            print("free item eth")
            free(c_obj)

cdef class Py2CFlowItemIPV4Convertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef:
            clibdpdk.rte_flow_item_ipv4 *c_ipv4

        if pyObj is None:
            return NULL

        c_ipv4 = <clibdpdk.rte_flow_item_ipv4 *>malloc(sizeof(clibdpdk.rte_flow_item_ipv4))
        if not c_ipv4:
            MemoryError("No free memory")

        memset(<void*>c_ipv4, 0, sizeof(clibdpdk.rte_flow_item_ipv4))

        c_ipv4.hdr.version_ihl     = pyObj.hdr.version_ihl
        c_ipv4.hdr.type_of_service = pyObj.hdr.type_of_service
        c_ipv4.hdr.total_length    = rte_le_to_be_16(pyObj.hdr.total_length)
        c_ipv4.hdr.packet_id       = rte_le_to_be_16(pyObj.hdr.packet_id)
        c_ipv4.hdr.fragment_offset = rte_le_to_be_16(pyObj.hdr.fragment_offset)
        c_ipv4.hdr.time_to_live    = pyObj.hdr.time_to_live
        c_ipv4.hdr.next_proto_id   = pyObj.hdr.next_proto_id
        c_ipv4.hdr.hdr_checksum    = rte_le_to_be_16(pyObj.hdr.hdr_checksum)
        c_ipv4.hdr.src_addr        = rte_le_to_be_32(pyObj.hdr.src_addr)
        c_ipv4.hdr.dst_addr        = rte_le_to_be_32(pyObj.hdr.dst_addr)

        print("Finish ipv4:", c_ipv4[0])
        return <void*>c_ipv4

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        if reserved == NULL:
            print("free item ipv4")
            free(c_obj)

cdef class Py2CFlowItemUDPConvertor(Py2CConvertor):
    cdef void * convert(self, pyObj, convert_dict={}, void * reserved = NULL):
        cdef:
            clibdpdk.rte_flow_item_udp * c_udp

        if pyObj is None:
            return NULL

        c_udp = < clibdpdk.rte_flow_item_udp * > malloc(sizeof(clibdpdk.rte_flow_item_udp))
        if not c_udp:
            MemoryError("No free memory")

        memset( < void * > c_udp, 0, sizeof(clibdpdk.rte_flow_item_udp))

        c_udp.hdr.src_port = rte_le_to_be_16(pyObj.hdr.src_port)
        c_udp.hdr.dst_port = rte_le_to_be_16(pyObj.hdr.dst_port)
        c_udp.hdr.dgram_len = rte_le_to_be_16(pyObj.hdr.dgram_len)
        c_udp.hdr.dgram_cksum = rte_le_to_be_16(pyObj.hdr.dgram_cksum)

        print("Finish udp:", c_udp[0])
        return < void * > c_udp

    cdef void free_obj(self, void * c_obj, pyObj, convert_dict={}, void * reserved = NULL):
        if reserved == NULL:
            print("free item udp")
            free(c_obj)

cdef class Py2CFlowItemVLANConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef:
            clibdpdk.rte_flow_item_vlan *c_vlan

        if pyObj is None:
            return NULL

        c_vlan = <clibdpdk.rte_flow_item_vlan *>malloc(sizeof(clibdpdk.rte_flow_item_vlan))
        if not c_vlan:
            MemoryError("No free memory")

        memset(<void *>c_vlan, 0, sizeof(clibdpdk.rte_flow_item_vlan))

        c_vlan.tci = rte_le_to_be_16(pyObj.tci)
        c_vlan.inner_type = rte_le_to_be_16(pyObj.inner_type)
        print("Finish Vlan:", c_vlan[0])
        return <void *>c_vlan

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        if reserved == NULL:
            print("free item vlan")
            free(c_obj)

cdef class Py2CFlowItemPPPOEConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef:
            clibdpdk.rte_flow_item_pppoe *c_pppoe

        if pyObj is None:
            return NULL

        c_pppoe = <clibdpdk.rte_flow_item_pppoe *>malloc(sizeof(clibdpdk.rte_flow_item_pppoe))
        if not c_pppoe:
            MemoryError("No free memory")

        memset(<void *>c_pppoe, 0, sizeof(clibdpdk.rte_flow_item_pppoe))

        c_pppoe.version_type = pyObj.version_type
        c_pppoe.code = pyObj.code
        c_pppoe.session_id = rte_le_to_be_16(pyObj.session_id)
        c_pppoe.length = rte_le_to_be_16(pyObj.length)
        print("Finish PPPOE:", c_pppoe[0])
        return <void *>c_pppoe

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        if reserved == NULL:
            print("free item pppoe")
            free(c_obj)

cdef class Py2CFlowItemPPPOE_PROTO_IDConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef:
            clibdpdk.rte_flow_item_pppoe_proto_id *c_pppoe_proto_id

        if pyObj is None:
            return NULL

        c_pppoe_proto_id = <clibdpdk.rte_flow_item_pppoe_proto_id *>malloc(sizeof(clibdpdk.rte_flow_item_pppoe_proto_id))
        if not c_pppoe_proto_id:
            MemoryError("No free memory")

        memset(<void *>c_pppoe_proto_id, 0, sizeof(clibdpdk.rte_flow_item_pppoe_proto_id))

        c_pppoe_proto_id.proto_id = rte_le_to_be_16(pyObj.proto_id)
        print("Finish PPPOE_PROTO_ID:", c_pppoe_proto_id[0])
        return c_pppoe_proto_id

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        if reserved == NULL:
            print("free item pppoe_proto_id")
            free(c_obj)

cdef class Py2CListFlowActionConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef:
            clibdpdk.rte_flow_action *c_actions

        # TODO: check actions is list
        #
        if pyObj[-1].type_ != clibdpdk.RTE_FLOW_ACTION_TYPE_END:
            return NULL

        c_actions = <clibdpdk.rte_flow_action *>malloc(sizeof(clibdpdk.rte_flow_action) * len(pyObj))
        if c_actions == NULL:
            raise MemoryError("No free memory");

        memset(<void*>c_actions, 0, sizeof(clibdpdk.rte_flow_action) * len(pyObj))

        i = 0
        for p in pyObj:
            #print("pattern i %d, type %d" %(i, patterns[i].flow_item_type))
            py2c_convert(p, convert_dict, &c_actions[i])
            i = i + 1

        return <void*>c_actions

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        cdef clibdpdk.rte_flow_action *c_actions = <clibdpdk.rte_flow_action*>c_obj

        i = 0
        for p in pyObj:
            py2c_free(<void*>&c_actions[i], p, convert_dict, <void*>&c_actions[i])

        if reserved == NULL:
            print("free list action")
            free(c_obj)

cdef class Py2CFlowActionConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef clibdpdk.rte_flow_action *c_flow_action
        print(pyObj)

        if reserved == NULL:
            c_flow_action = <clibdpdk.rte_flow_action*>malloc(sizeof(clibdpdk.rte_flow_action))
            if c_flow_action == NULL:
                raise MemoryError("No free memory");
            memset(<void*>c_flow_action, 0, sizeof(clibdpdk.rte_flow_action))
        else:
            c_flow_action = <clibdpdk.rte_flow_action*>reserved

        c_flow_action.type = pyObj.type_
        if not pyObj.conf is None:
            c_flow_action.conf = py2c_convert(pyObj.conf, convert_dict)

        return c_flow_action

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        cdef clibdpdk.rte_flow_action *c_flow_action = <clibdpdk.rte_flow_action*>c_obj

        if not pyObj.conf is None:
            py2c_free(c_flow_action.conf, pyObj.conf, convert_dict)

        if reserved == NULL:
            print("free action")
            free(c_obj)


cdef class Py2CFlowActionCountConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef:
           clibdpdk.rte_flow_action_count *c_count

        if pyObj is None:
            return NULL

        print(pyObj)
        if reserved == NULL:
            c_count = <clibdpdk.rte_flow_action_count *>malloc(sizeof(clibdpdk.rte_flow_action_count))
            if c_count is NULL:
                raise MemoryError("No free memory")
        else:
            c_count = <clibdpdk.rte_flow_action_count *>reserved

        IF DPDK_VERSION == 'v21.08':
            c_count.shared = pyObj.shared
            c_count.reserved = pyObj.reserved
        c_count.id = pyObj.id

        print("Action count: ", c_count[0])
        return <void*>c_count


    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        if reserved == NULL:
            print("free action count conf")
            free(c_obj)


cdef class Py2CFlowActionVfConvertor(Py2CConvertor):
    cdef void* convert(self, pyObj, convert_dict={}, void* reserved=NULL):
        cdef:
            clibdpdk.rte_flow_action_vf *c_vf

        if pyObj is None:
            return NULL

        print(pyObj)
        if reserved == NULL:
            c_vf = <clibdpdk.rte_flow_action_vf *>malloc(sizeof(clibdpdk.rte_flow_action_vf))
            if not c_vf:
                raise MemoryError("No free memory")
        else:
            c_vf = <clibdpdk.rte_flow_action_vf *>reserved

        c_vf.reserved = pyObj.reserved
        c_vf.original = pyObj.original
        c_vf.id = pyObj.id
        print("Action vf: ", c_vf[0])

        return <void*>c_vf

    cdef void free_obj(self, void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
        if reserved == NULL:
            print("free action vf conf")
            free(c_obj)


cdef void* py2c_convert(pyObj, convert_dict={}, void* reserved=NULL):
    cdef void* ret = NULL
    cdef Py2CConvertor py2c_convertor

    if pyObj is None:
        return NULL

    if isinstance(pyObj, list):
        if len(pyObj) > 0:
            py2c_convertor = convert_dict["list_" + pyObj[0].__class__.__name__]
            ret = py2c_convertor.convert(pyObj, convert_dict, reserved)
    else:
        py2c_convertor = convert_dict[pyObj.__class__.__name__]
        ret = py2c_convertor.convert(pyObj, convert_dict, reserved)

    return ret


cdef void* py2c_free(void* c_obj, pyObj, convert_dict={}, void* reserved=NULL):
    cdef void* ret = NULL
    cdef Py2CConvertor py2c_convertor

    if pyObj is None:
        return NULL

    if isinstance(pyObj, list):
        if len(pyObj) > 0:
            py2c_convertor = convert_dict["list_" + pyObj[0].__class__.__name__]
            py2c_convertor.free_obj(c_obj, pyObj, convert_dict, reserved)
    else:
        #print(pyObj.__class__.__name__)
        py2c_convertor = convert_dict[pyObj.__class__.__name__]
        py2c_convertor.free_obj(c_obj, pyObj, convert_dict, reserved)



cdef class PyFlow:
    cdef:
        void *_ptr
        char *_flow_str

    @staticmethod
    cdef PyFlow from_c_rte_flow(void* c_rte_flow, char *_flow_str):
        cdef PyFlow pyFlow = PyFlow.__new__(PyFlow)
        pyFlow._ptr = c_rte_flow
        pyFlow._flow_str = _flow_str
        return pyFlow

    cdef void* get_ptr_rte_flow(self):
        return self._ptr

    cdef char* get_flow_string(self):
        return self._flow_str

    cdef cdealloc(self):
        print("__dealloc__ was called")
        free(self._flow_str)

class FlowPool:
    def __init__(self):
        self.__pool = {}

    def append_flow(self, port_id, py_flow):
        if port_id not in self.__pool:
            self.__pool[port_id] = []

        self.__pool[port_id].append(py_flow)
        flow_idx = len(self.__pool[port_id])-1
        return flow_idx

    def get_flows(self, port_id):
        if port_id not in self.__pool:
            raise Exception("Port is not existing.")

        return self.__pool[port_id]

    def get_flow(self, port_id, flow_idx):
        if port_id not in self.__pool:
            raise Exception("Port is not existing.")

        if flow_idx >= len(self.__pool[port_id]) or self.__pool[port_id][flow_idx] is None:
            raise Exception("Flow is not existing.")

        return self.__pool[port_id][flow_idx]

    def get_flow_cnt(self, port_id):
        if port_id not in self.__pool:
            raise Exception("Port is not existing.")

        return len(self.__pool[port_id])

    def remove_flow(self, port_id, flow_idx):
        cdef PyFlow pyFlow
        if port_id not in self.__pool:
            raise Exception("Port is not existing.")

        if flow_idx >= len(self.__pool[port_id]) or self.__pool[port_id][flow_idx] is None:
            raise Exception("Flow is not existing.")

        pyFlow = self.__pool[port_id][flow_idx]
        pyFlow.cdealloc()
        self.__pool[port_id][flow_idx] = None

    # reset flow index after flow_flush
    def reset_flows(self, port_id):
        if port_id in self.__pool:
            self.__pool[port_id] = []

    def is_empty(self):
        if len(self.__pool.keys()) == 0:
            return True

        return False

flow_pool = FlowPool()

class RetryPolicy:
    def __init__(self):
        self.__interval = 0
        self.__limit = 0
        self.__failures = 0
        self.__fail_busy = 0

    def set_policy(self, interval, limit):
        self.__interval = interval
        self.__limit = limit
        print('set interval = %d limit = %d' %(self.__interval, self.__limit))

    def can_retry(self):
        self.__failures += 1
        res = (clibdpdk.per_lcore__rte_errno == clibdpdk.EAGAIN)
        if res:
            clibdpdk.per_lcore__rte_errno = 0
            self.__fail_busy += 1
            time.sleep(self.__interval / 1000)
            print('fails %d times fail_busy = %d' %(self.__failures, self.__fail_busy))
        return res

    def get_limit(self):
        return range(0, self.__limit + 1)

def set_retry_policy(interval, limit):
    retry_policy.set_policy(interval, limit)

retry_policy = RetryPolicy()

cdef char *flow_to_string(clibdpdk.rte_flow_attr *c_attr,  \
                        clibdpdk.rte_flow_item *c_patterns,     \
                        clibdpdk.rte_flow_action *c_actions):
    cdef:
        clibdpdk.rte_flow_conv_rule c_rule
        clibdpdk.rte_flow_conv_rule *c_new_rule
        clibdpdk.rte_flow_error c_error
        char *c_name
        int c_ret
        char *c_flow_str

    c_rule.attr_ro = c_attr
    c_rule.pattern_ro = c_patterns
    c_rule.actions_ro = c_actions

    # to clibdpdk.rte_flow_conv_rule
    c_ret = clibdpdk.rte_flow_conv(clibdpdk.RTE_FLOW_CONV_OP_RULE, NULL, 0, &c_rule, &c_error)
    if c_ret < 0:
        print("error:", c_error.message)
        raise Exception(c_error.message)

    c_new_rule = <clibdpdk.rte_flow_conv_rule *>malloc(sizeof(clibdpdk.rte_flow_conv_rule) + c_ret)
    if not c_new_rule:
        raise MemoryError("No free memory")
    memset(<void*>c_new_rule, 0, sizeof(clibdpdk.rte_flow_conv_rule) + c_ret)

    if clibdpdk.rte_flow_conv(clibdpdk.RTE_FLOW_CONV_OP_RULE, c_new_rule, \
                    c_ret, &c_rule, &c_error) < 0:
        print("error:", c_error.message)
        free(c_new_rule)
        raise Exception(c_error.message)

    # to string
    c_attr = c_new_rule.attr
    c_patterns = c_new_rule.pattern
    c_actions = c_new_rule.actions

    flow_string = str(c_attr[0].group) + "\t" \
            + str(c_attr[0].priority) + "\t"

    if c_attr[0].ingress == 1:
        flow_string = flow_string + 'i'
    else:
        flow_string = flow_string + '-'



    if c_attr[0].egress == 1:
        flow_string = flow_string + 'e'
    else:
        flow_string = flow_string + '-'

    if c_attr[0].transfer == 1:
        flow_string = flow_string + "t\t"
    else:
        flow_string = flow_string + "-\t"

    i = 0
    while c_patterns[i].type != clibdpdk.RTE_FLOW_ITEM_TYPE_END:
        if (clibdpdk.rte_flow_conv(clibdpdk.RTE_FLOW_CONV_OP_ITEM_NAME_PTR, \
                    &c_name, sizeof(c_name), <void*>c_patterns[i].type,     \
                            NULL) <= 0):
            c_name = b'[UNKNOWN]'

        if c_patterns[i].type != clibdpdk.RTE_FLOW_ITEM_TYPE_VOID:
            flow_string = flow_string + str(c_name, 'utf-8') + ' '

        i = i + 1

    flow_string = flow_string + "=>"

    i = 0
    while c_actions[i].type != clibdpdk.RTE_FLOW_ACTION_TYPE_END:
        if (clibdpdk.rte_flow_conv(clibdpdk.RTE_FLOW_CONV_OP_ACTION_NAME_PTR,   \
                    &c_name, sizeof(c_name), <void*>c_actions[i].type,          \
                            NULL) <= 0):
            c_name = b'[UNKNOWN]'

        if c_actions[i].type != clibdpdk.RTE_FLOW_ACTION_TYPE_VOID:
            flow_string = flow_string + str(c_name, 'utf-8') + ' '

        i = i + 1

    try:
        c_flow_str = <char*>malloc(len(flow_string)+1)
        memset(<void*>c_flow_str, 0, len(flow_string)+1)

    except Exception as e:
        free(c_new_rule)
        raise Exception("No free memory")

    flow_bytes = bytes(flow_string, encoding="utf-8")
    for i in range(len(flow_bytes)):
        c_flow_str[i] = flow_bytes[i]

    free(c_new_rule)
    return c_flow_str

