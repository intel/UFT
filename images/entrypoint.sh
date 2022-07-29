#!/bin/bash
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
####
# This script generate server config file dynamically from VF PCI address
# given in Environment varible exported by device plugin in following
# format: PCIDEVICE_INTEL_COM_INTEL_ENP24S0F0=0000:18:02.2
####
rawpci=$(env | grep PCIDEVICE_ | awk -F'=' '{ print $2 }')
pciids=(${rawpci//,/ })

SERVER_CONF_FILE=/opt/dcf/server_conf.yaml

## Exit if device ID's are not found
if [ -z "$pciids" ]; then
    echo "No PCI device info found."
    exit 1
fi

echo "Generating server_conf.yaml file..."
cat > $SERVER_CONF_FILE <<EOF
server :
    ld_lib : "${UFT_INSTALL_PATH}"
ports_info :
EOF

for id in ${pciids[@]}; do
cat >> $SERVER_CONF_FILE <<EOF
    - pci  : "$id"
      mode : dcf
EOF
done

echo "Done!"

cat $SERVER_CONF_FILE

nohup python3 -u server.py &
server_pid=$!
echo "server's pid=${server_pid}"

function sig_handler()
{
    echo "Docker stopped, kill SIGTERM to ${server_pid}"
    kill -SIGTERM ${server_pid}
    sleep 1
    exit 0
}

trap "sig_handler" SIGINT SIGTERM EXIT

while true
do
    sleep 3
done
