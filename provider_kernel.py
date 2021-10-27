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

import flow_pb2 as pb

def Create(request, context):
    print("kerenl implement: Create: ip link set...")
    return pb.ResponseFlowCreate(error_info=pb.rte_flow_error(
                                type=-1, mesg='Create now not supported by kernel, wait implement.'))

def Destroy(request, context):
    print("kerenl implement: Destroy: ip link set...")
    return pb.ResponseFlow(error_info=pb.rte_flow_error(
                            type=-1, mesg='Destroy now not supported by kernel, wait implement.'))

def Validate(request, context):
    print("kerenl implement: Validate: ip link set...")
    return pb.ResponseFlow(error_info=pb.rte_flow_error(
                            type=-1, mesg='Validate now not supported by kernel, wait implement.'))

def Flush(request, context):
    print("kerenl implement: Flush: ip link set...")
    return pb.ResponseFlow(error_info=pb.rte_flow_error(
                            type=-1, mesg='Flush now not supported by kernel, wait implement.'))

def Query(request, context):
    print("kerenl implement: Query: ip link set...")
    return pb.ResponseFlowQuery(error_info=pb.rte_flow_error(
                                type=-1, mesg='Query now not supported by kernel, wait implement.'))

def List(request, context):
    print("kerenl implement: List: ip link set...")
    return pb.ResponseFlowList()

def Isolate(request, context):
    print("kerenl implement: Isolate: ip link set...")
    return pb.ResponseFlow(error_info=pb.rte_flow_error(
                            type=-1, mesg='Isolate now not supported by kernel, wait implement.'))

def init_ports(ports_config, server_config):
    print("kerenl implement: Initalize: ip link set...")
    return None

def handle_exit(port_config):
    print("kerenl implement: handle exit...")
    return True
