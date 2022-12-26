#! /usr/bin/env python3
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

import os
import sys
import grpc
import time
from concurrent import futures
import atexit
import signal
#from pip._vendor.requests.api import request
#from lib2to3.fixes.fix_input import context

sys.path.append("./rpc")
sys.path.append("./lib")

import flow_pb2 as pb
import flow_pb2_grpc as pb_grpc
from flow_pb2_grpc import add_FlowServiceServicer_to_server
import qos_pb2
import qos_pb2_grpc
from qos_pb2_grpc import add_QosServiceServicer_to_server
import faulthandler
import yaml
from grpc_reflection.v1alpha import reflection
from comm_struct import QosError

faulthandler.enable()
server_config_file = './server_conf.yaml'

import provider_dcf
import provider_kernel
providers = {
    "dcf": provider_dcf,
    "kernel": provider_kernel
}

ports = []

class Flow(pb_grpc.FlowServiceServicer):
    def __init__(self):
        pass

    def Validate(self, request, context):
        port_id = request.port_id
        err = check_port_valid(port_id, ports)
        if err.type == -1:
            return pb.ResponseFlow(error_info=err)

        port_mode = ports[port_id]["mode"]
        # the real port index of current mode
        request.port_id = ports[port_id]["port_mode_index"]

        resp = providers[port_mode].Validate(request, context)
        return resp

    def Create(self, request, context):
        port_id = request.port_id
        err = check_port_valid(port_id, ports)
        if err.type == -1:
            return  pb.ResponseFlowCreate(error_info=err)

        port_mode = ports[port_id]["mode"]
        # the real port index of current mode
        request.port_id = ports[port_id]["port_mode_index"]

        resp = providers[port_mode].Create(request, context)

        return resp

    def Destroy(self, request, context):
        port_id = request.port_id
        err = check_port_valid(port_id, ports)
        if err.type == -1:
            return  pb.ResponseFlow(error_info=err)

        port_mode = ports[port_id]["mode"]
        # the real port index of current mode
        request.port_id = ports[port_id]["port_mode_index"]

        resp = providers[port_mode].Destroy(request, context)
        return resp

    def Flush(self, request, context):
        port_id = request.port_id
        err = check_port_valid(port_id, ports)
        if err.type == -1:
            return  pb.ResponseFlow(error_info=err)

        port_mode = ports[port_id]["mode"]
        # the real port index of current mode
        request.port_id = ports[port_id]["port_mode_index"]

        resp = providers[port_mode].Flush(request, context)
        return resp

    def Query(self, request, context):
        port_id = request.port_id
        err = check_port_valid(port_id, ports)
        if err.type == -1:
            return  pb.ResponseFlowQuery(error_info=err)

        port_mode = ports[port_id]["mode"]
        # the real port index of current mode
        request.port_id = ports[port_id]["port_mode_index"]

        resp = providers[port_mode].Query(request, context)
        return resp

    def List(self, request, context):
        port_id = request.port_id
        err = check_port_valid(port_id, ports)
        if err.type == -1:
            return  pb.ResponseFlowList()

        port_mode = ports[port_id]["mode"]
        # the real port index of current mode
        request.port_id = ports[port_id]["port_mode_index"]

        resp = providers[port_mode].List(request, context)
        return resp

    def Isolate(self, request, context):
        pass

    def ListPorts(self, request, context):
        resp = pb.ResponsePortList()
        for port_id in range(len(ports)):
            one_port = pb.ports_information()
            one_port.port_id = port_id
            one_port.port_pci = ports[port_id]['pci']
            one_port.port_mode = ports[port_id]['mode']

            if ports[port_id]['mode'] == 'dcf':
                reprs = providers['dcf'].get_repr_info(one_port.port_pci)
                for i, repr_id in enumerate(reprs):
                    one_repr = pb.repr_infomation()
                    one_repr.vf_id = i + 1
                    one_repr.repr_id = repr_id
                    one_port.reprentor.append(one_repr)

            resp.ports.append(one_port)
        return resp

class Qos(qos_pb2_grpc.QosServiceServicer):
    def __init__(self):
        pass

    def Add_TM_Node(self, request, context):
        port_id = request.port_id
        err = check_port_valid(port_id, ports)
        if err.type == -1:
            return pb.ResponseFlow(error_info=err)

        port_mode = ports[port_id]["mode"]
        # the real port index of current mode
        request.port_id = ports[port_id]["port_mode_index"]
        port_id = request.port_id

        profile_id = request.profile_id
        resp = qos_pb2.ResponseRet()

        print("add root node for port %d" % port_id)
        root_node_id = 10000
        #root node have no parent and profile, so -1, -1
        try:
            ret = providers[port_mode].Qos_node_add(port_id, root_node_id, -1, 0, -1)
        except Exception as e:
            print("exc: %s" % e)
            resp.ret = -1
            resp.msg = str(e)

        for i in range(0, request.tc_num):
            tc_node_id = 1000 - 100 * i
            print("add tc %s to port %d" % (i, port_id))
            try:
                ret = providers[port_mode].Qos_node_add(port_id, tc_node_id, root_node_id, 1, -1)
            except Exception as e:
                print("exc: %s" % e)
                resp.ret = -1
                resp.msg = str(e)

            for j in range(0, request.vf_num):
                vsi_node_id = i * 2 + j
                print("add vf %d to tc %d" % (vsi_node_id, i))
                try:
                    ret = providers[port_mode].Qos_node_add(port_id, vsi_node_id, tc_node_id, 2, profile_id)
                except Exception as e:
                    print("exc: %s" % e)
                    resp.ret = -1
                    resp.msg = str(e)

        print("commit port %d scheduel tree to hw" % port_id)
        try:
            ret = providers[port_mode].Qos_commit(port_id)
        except Exception as e:
            print("exc: %s" % e)
            resp.ret = -1
            resp.msg = str(e)
        else:
            resp.ret = 0
            resp.msg = "ok"
        return resp

    def Set_Node_BW(self, request, context):
        port_id = request.port_id
        err = check_port_valid(port_id, ports)
        if err.type == -1:
            return pb.ResponseFlow(error_info=err)

        port_mode = ports[port_id]["mode"]
        # the real port index of current mode
        request.port_id = ports[port_id]["port_mode_index"]
        port_id = request.port_id

        profile_id = request.profile_id
        cbw = request.committed_bw
        pbw = request.peak_bw

        print("set cbw %d, pbw %d as profile %d" %
              (cbw, pbw, profile_id))

        resp = qos_pb2.ResponseRet()

        try:
            ret = providers[port_mode].Qos_shaper_profile_add(port_id, profile_id, cbw, pbw)
        except Exception as e:
            print("exc: %s" % e)
            resp.ret = -1
            resp.msg = str(e)
        else:
            resp.ret = ret
            resp.msg = "ok"

        return resp

    def Del_Node_BW(self, request, context):
        port_id = request.port_id
        err = check_port_valid(port_id, ports)
        if err.type == -1:
            return pb.ResponseFlow(error_info=err)

        port_mode = ports[port_id]["mode"]
        # the real port index of current mode
        request.port_id = ports[port_id]["port_mode_index"]
        port_id = request.port_id

        profile_id = request.profile_id
        print("delete profile %d" %  profile_id)

        resp = qos_pb2.ResponseRet()

        try:
            ret = providers[port_mode].Qos_shaper_profile_del(port_id, profile_id)
        except Exception as e:
            print("exc: %s" % e)
            resp.ret = -1
            resp.msg = str(e)
        else:
            resp.ret = ret
            resp.msg = "ok"

        return resp

    def Get_Node_BW(self, request, context):
        print("Get_Node_BW port_id %u" % request.port_id)

        resp = qos_pb2.ResponseBW()
        resp.ret = 0
        resp.committed_bw = 1000000
        resp.peak_bw = 1000000000
        resp.msg = "ok"
        return resp

def check_port_valid(input_port, ports):
    err = pb.rte_flow_error()
    if len(ports) <= input_port:
        print("client input a invalid port id %d" % input_port)
        err.type = -1
        err.mesg = "Port id error, valid port id from 0 to %d" % (len(ports) - 1)

    return err

def init_ports(server_config):
    global ports
    if len(ports) < 1:
        raise Exception('please config the ports info in config file')

    # get all mode type in ports
    mode_list = set(port['mode'] for port in ports)
    for cur_mode in mode_list:
        cur_port_list = []
        for port_config in ports:
            if port_config['mode'] == cur_mode:
                cur_port_list.append(port_config)

        try:
            # return the sort ports in current mode
            sort_ports = providers[cur_mode].init_ports(cur_port_list, server_config)
        except Exception as err:
            print(err)
            exit(1)

        # add key-value in ports, depend on current mode real ports sort information
        if sort_ports is None:
            sort_ports = cur_port_list

        for r_port_config in sort_ports:
            r_index = r_port_config["port_mode_index"]
            for p_index, p_port_config in enumerate(ports):
                if p_port_config["pci"] == r_port_config["pci"]:
                    ports[p_index]["port_mode_index"] = r_index
        print(ports)

def init_retry(retry_cfg):
    interval = None
    limit = None

    if retry_cfg is not None and isinstance(retry_cfg, dict):
        if 'interval' in retry_cfg and retry_cfg['interval'] is not None:
            interval = retry_cfg['interval']
        if 'limit' in retry_cfg and retry_cfg['limit'] is not None:
            limit = retry_cfg['limit']

        if interval is not None and not isinstance(interval, int):
                raise Exception('retry_conf: interval must be integer')
        if limit is not None and not isinstance(limit, int):
            raise Exception('retry_conf: limit must be integer')

    # just only support dcf
    providers['dcf'].init_retry(interval, limit)

def handle_exit():
    global ports
    mode_list = set(port['mode'] for port in ports)
    for cur_mode in mode_list:
        for port_config in ports:
            if port_config['mode'] == cur_mode:
                providers[cur_mode].handle_exit(port_config)

def signal_handler(signum, frame):
    print("recv signal ", signum)
    sys.exit()

def main():
    global ports
    print('do eal init ...')
    fd = open('./server_conf.yaml', 'r', encoding='utf-8')
    cfg = fd.read()
    fd.close()
    cfg_info = yaml.safe_load(cfg)
    server_info = cfg_info['server']
    ports = cfg_info['ports_info']

    print(ports)
    init_ports(server_info)

    print("grpc server start ...")
    server_thread = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    add_FlowServiceServicer_to_server(Flow(), server_thread)
    add_QosServiceServicer_to_server(Qos(), server_thread)

    # add reflection of FlowService
    SERVICE_NAMES = (
        pb.DESCRIPTOR.services_by_name['FlowService'].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server_thread)

    if 'server_port' in server_info.keys():
        try:
            server_port = int(server_info['server_port'])
        except (ValueError, TypeError):
            print("Error: Invalid server port.")
            return
        else:
            if 'cert_key' not in server_info or server_info['cert_key'] is None:
                print("server_conf.yaml : 'cert_key' must be assigned.")
                return
            if 'cert_certificate' not in server_info or server_info['cert_certificate'] is None:
                print("server_conf.yaml : 'cert_certificate' must be assigned")
                return

            with open(server_info['cert_key'], 'rb') as f:
                private_key = f.read()
            with open(server_info['cert_certificate'], 'rb') as f:
                certificate_chain = f.read()
            server_credentials = grpc.ssl_server_credentials(((private_key, certificate_chain),))
            server_thread.add_secure_port('localhost:%d' % server_port, server_credentials)
    else:
        server_thread.add_insecure_port('localhost:50051')

    atexit.register(handle_exit)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    server_thread.start()

    try:
        while(1):
            print('now in server cycle')
            time.sleep(10000)
    except KeyboardInterrupt as e:
        server_thread.stop(grace=True)

if __name__ == "__main__":
    main()
