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

import dpdk
import comm_struct
import flow_pb2 as pb
import google.protobuf.pyext._message

mapping = {
    "flow.rte_flow_attr": comm_struct.rte_flow_attr,

    "flow.rte_flow_item": comm_struct.rte_flow_item,
    "flow.rte_flow_item.type": "type_",
    "flow.rte_flow_item_eth": comm_struct.rte_flow_item_eth,
    "flow.rte_flow_item_eth.type": "type_",
    "flow.rte_ether_addr": comm_struct.rte_ether_addr,
    "flow.rte_ipv4_hdr": comm_struct.rte_ipv4_hdr,
    "flow.rte_flow_item_ipv4": comm_struct.rte_flow_item_ipv4,
    "flow.rte_flow_item_any": comm_struct.rte_flow_item_any,
    "flow.rte_flow_item_vf": comm_struct.rte_flow_item_vf,
    "flow.rte_flow_item_phy_port": comm_struct.rte_flow_item_phy_port,
    "flow.rte_flow_item_port_id": comm_struct.rte_flow_item_port_id,
    "flow.rte_flow_item_raw": comm_struct.rte_flow_item_raw,
    "flow.rte_flow_item_vlan": comm_struct.rte_flow_item_vlan,
    "flow.rte_ipv6_hdr": comm_struct.rte_ipv6_hdr,
    "flow.rte_flow_item_ipv6": comm_struct.rte_flow_item_ipv6,
    "flow.rte_icmp_hdr": comm_struct.rte_icmp_hdr,
    "flow.rte_flow_item_icmp": comm_struct.rte_flow_item_icmp,
    "flow.rte_udp_hdr": comm_struct.rte_udp_hdr,
    "flow.rte_flow_item_udp": comm_struct.rte_flow_item_udp,
    "flow.rte_tcp_hdr": comm_struct.rte_tcp_hdr,
    "flow.rte_flow_item_tcp": comm_struct.rte_flow_item_tcp,
    "flow.rte_sctp_hdr": comm_struct.rte_sctp_hdr,
    "flow.rte_flow_item_sctp": comm_struct.rte_flow_item_sctp,
    "flow.rte_flow_item_vxlan": comm_struct.rte_flow_item_vxlan,
    "flow.rte_flow_item_e_tag": comm_struct.rte_flow_item_e_tag,
    "flow.rte_flow_item_nvgre": comm_struct.rte_flow_item_nvgre,
    "flow.rte_flow_item_mpls": comm_struct.rte_flow_item_mpls,
    "flow.rte_flow_item_gre": comm_struct.rte_flow_item_gre,
    "flow.rte_flow_item_fuzzy": comm_struct.rte_flow_item_fuzzy,
    "flow.rte_flow_item_gtp": comm_struct.rte_flow_item_gtp,
    "flow.rte_esp_hdr": comm_struct.rte_esp_hdr,
    "flow.rte_flow_item_esp": comm_struct.rte_flow_item_esp,
    "flow.rte_flow_item_geneve": comm_struct.rte_flow_item_geneve,
    "flow.rte_flow_item_vxlan_gpe": comm_struct.rte_flow_item_vxlan_gpe,
    "flow.rte_flow_item_arp_eth_ipv4": comm_struct.rte_flow_item_arp_eth_ipv4,
    "flow.rte_flow_item_ipv6_ext": comm_struct.rte_flow_item_ipv6_ext,
    "flow.rte_flow_item_icmp6": comm_struct.rte_flow_item_icmp6,
    "flow.rte_flow_item_icmp6.type": "type_",
    "flow.rte_flow_item_icmp6_nd_ns": comm_struct.rte_flow_item_icmp6_nd_ns,
    "flow.rte_flow_item_icmp6_nd_ns.type": "type_",
    "flow.rte_flow_item_icmp6_nd_na": comm_struct.rte_flow_item_icmp6_nd_na,
    "flow.rte_flow_item_icmp6_nd_na.type": "type_",
    "flow.rte_flow_item_icmp6_nd_opt": comm_struct.rte_flow_item_icmp6_nd_opt,
    "flow.rte_flow_item_icmp6_nd_opt_sla_eth": comm_struct.rte_flow_item_icmp6_nd_opt_sla_eth,
    "flow.rte_flow_item_meta": comm_struct.rte_flow_item_meta,
    "flow.rte_flow_item_mark": comm_struct.rte_flow_item_mark,
    "flow.rte_flow_item_gtp_psc": comm_struct.rte_flow_item_gtp_psc,
    "flow.rte_flow_item_pppoe": comm_struct.rte_flow_item_pppoe,
    "flow.rte_flow_item_pppoe_proto_id": comm_struct.rte_flow_item_pppoe_proto_id,
    "flow.rte_flow_item_nsh": comm_struct.rte_flow_item_nsh,
    "flow.rte_flow_item_igmp": comm_struct.rte_flow_item_igmp,
    "flow.rte_flow_item_igmp.type": "type_",
    "flow.rte_flow_item_ah": comm_struct.rte_flow_item_ah,
    "flow.rte_higig2_frc": comm_struct.rte_higig2_frc,
    "flow.rte_higig2_ppt_type0": comm_struct.rte_higig2_ppt_type0,
    "flow.rte_higig2_hdr": comm_struct.rte_higig2_hdr,
    "flow.rte_flow_item_higig2_hdr": comm_struct.rte_flow_item_higig2_hdr,
    "flow.rte_flow_item_tag": comm_struct.rte_flow_item_tag,
    "flow.rte_flow_item_l2tpv3oip": comm_struct.rte_flow_item_l2tpv3oip,

    "flow.rte_flow_action": comm_struct.rte_flow_action,
    "flow.rte_flow_action.type": "type_",
    "flow.rte_flow_action_vf": comm_struct.rte_flow_action_vf,
    "flow.rte_flow_action_count": comm_struct.rte_flow_action_count,
}

def proto2py_convertor(pb_obj_in, convert_dict={}):
    if isinstance(pb_obj_in, google.protobuf.any_pb2.Any):
        if pb_obj_in.type_url == '':
            return None
        #TODO: Need to rewrite follow by protobuf spec
        type_name = pb_obj_in.type_url.split("/")[-1].split(".")[-1]
        proto_type_class = getattr(pb, type_name, None)
        proto_obj = proto_type_class()
        pb_obj_in.Unpack(proto_obj)
    else:
        proto_obj = pb_obj_in

    if isinstance(proto_obj, google.protobuf.pyext._message.RepeatedCompositeContainer):
        py_obj = []
        for nested_obj in proto_obj:
            py_obj.append(proto2py_convertor(nested_obj, convert_dict))
    else:
        print(proto_obj.DESCRIPTOR.full_name)
        py_fields={}
        for field in proto_obj.DESCRIPTOR.fields:
            py_field_name = field.name

            # Also support to map/convert the field name to py data struct
            if field.full_name in convert_dict:
                py_field_name = convert_dict[field.full_name]

            if field.message_type != None:
                py_fields[py_field_name] = proto2py_convertor(getattr(proto_obj, field.name), convert_dict)
            else:
                py_fields[py_field_name] = getattr(proto_obj, field.name)

        py_obj = convert_dict[proto_obj.DESCRIPTOR.full_name](**py_fields)

    return py_obj

def Create(request, context):
    attr = proto2py_convertor(request.attr, mapping)
    patterns = proto2py_convertor(request.pattern, mapping)
    actions = proto2py_convertor(request.action, mapping)
    print(attr, patterns, actions)
    resp = pb.ResponseFlowCreate()
    port_id = request.port_id

    try:
        print(attr)
        ret = dpdk.rte_flow_create(port_id, attr, patterns, actions)
        resp.flow_id = ret
    except Exception as e:
        print(e)
        resp.error_info.type = -1
        resp.error_info.mesg = str(e)
    return resp

def Validate(request, context):
    attr = proto2py_convertor(request.attr, mapping)
    patterns = proto2py_convertor(request.pattern, mapping)
    actions = proto2py_convertor(request.action, mapping)
    print(attr, patterns, actions)
    err = pb.rte_flow_error()
    port_id = request.port_id
    try:
        dpdk.rte_flow_validate(port_id, attr, patterns, actions)
    except Exception as e:
        print(e)
        err.type = -1
        err.mesg = str(e)
    return pb.ResponseFlow(error_info=err)

def Destroy(request, context):
    err = pb.rte_flow_error()
    port_id = request.port_id
    flow_id = request.flow_id
    try:
        dpdk.rte_flow_destroy(port_id, flow_id)
    except Exception as e:
        print (e)
        err.type = -1
        err.mesg = str(e)
    return pb.ResponseFlow(error_info=err)

def Flush(request, context):
    err = pb.rte_flow_error()
    port_id = request.port_id
    try:
        dpdk.rte_flow_flush(port_id)
    except Exception as e:
        print(e)
        err.type = -1
        err.mesg = str(e)
    return pb.ResponseFlow(error_info=err)

def Query(request, context):
    err = pb.rte_flow_error()
    data = pb.rte_flow_query_count()
    port_id = request.port_id
    flow_id = request.flow_id
    action = request.action
    try:
        ret = dpdk.rte_flow_query(port_id, flow_id,action)
        data.reset = ret.reset
        data.hits_set = ret.hits_set
        data.bytes_set = ret.bytes_set
        data.reserved = ret.reserved
        data.hits = ret.hits
        data.bytes = ret.bytes
        print (ret)
    except Exception as e:
        print (e)
        err.type = -1
        err.mesg = str(e)
    return pb.ResponseFlowQuery(error_info=err, data=data)

def List(request, context):
    port_id = request.port_id
    result_list = pb.ResponseFlowList()
    try:
        ret = dpdk.rte_flow_list(port_id)
        for result in ret:
            flow_info = pb.rte_flow_list_result(flow_id=result.flow_id, description=result.description)
            result_list.results.append(flow_info)
    except Exception as e:
        print (e)
    return result_list

def Isolate(request, context):
    return pb.ResponseFlow()

def takecompkey(elem):
    return elem['pci']

def init_ports(ports_config, server_config):
    pci_info = '-a %s,cap=dcf'

    ports_config.sort(key=takecompkey)
    pci_list = []
    print(ports_config)
    for port_config in ports_config:
        pci_list.append(pci_info % port_config['pci'])
    pci_list_str = ' '.join(pci_list)

    # param = 'a.out -c 0x30 -n 4 -d %s %s --file-prefix=dcf --'
    if 'ld_lib' in server_config and server_config['ld_lib'] is not None:
        ld_lib = server_config['ld_lib']
    else:
        ld_lib = '/usr/local/lib'
    param = 'a.out -c 0x30 -n 4 %s -d %s --file-prefix=dcf --'
    # param = 'a.out -c 0x30 -n 4 -d %s %s --log-level=pmd.net.ice.driver:8 --file-prefix=dcf --'
    param = param % (pci_list_str, ld_lib)
    print('the dcf cmd line is: %s' % param)
    arg_list = param.split()

    ret = dpdk.rte_eal_init(arg_list)
    if ret < 0:
        raise Exception("DPDK eal init failed (%d)" % ret)

    # confirm all ports are valid by checking the port ids are successive.
    # rte_eth_find_next_owned_by returns max_port if there is no other valid port.
    # the value of max_port in dpdk is configurable, default is 32
    for port_id in range(len(pci_list)):
       if (port_id != dpdk.rte_eth_find_next_owned_by(port_id, 0)):
           raise Exception("Port %d init failed" % port_id);

    return ports_config

def handle_exit(port_config):
    try:
        dpdk.rte_flow_flush(port_config["port_mode_index"])
    except Exception as e:
        print(e)
