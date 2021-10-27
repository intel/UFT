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

import sys
sys.path.append("./rpc")
sys.path.append("./lib")

from rpc import grpc_server
import dpdk

import faulthandler

faulthandler.enable()

def eal_init(argv):
    #param = argv
    # if len(sys.argv) == 1:
    #     # get params from env
    #     argv_str = os.getenv('EAL_PARAMS')
    #     param = param + str(argv_str).split(' ')

    param = "-c 0x6 -n 4 --file-prefix=dcfvf0  --"
    dpdk.do_eal_init(param.split(" "))

def main():
    eal_init(sys.argv)
    print("grpc server start ...")
    grpc_server.run('localhost:50051')

if __name__ == "__main__":
    main()
