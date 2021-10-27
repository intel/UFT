<!-- Copyright(c) 2021 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

-->

Build:
    docker build -t uft -f Dockerfile.third . \
    --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy

Run:
    docker run -v /dev/hugepages:/dev/hugepages -v /usr/lib/firmware:/usr/lib/firmware:rw \
    -e  PCIDEVICE_INTEL_COM_INTEL_ENS801F0=0000:83:01.0 --net=host --cap-add IPC_LOCK \
    --cap-add SYS_NICE --device /dev/vfio:/dev/vfio uft

FAQ:
1. How to run docker in none-root mode?
   We must make sure the user has the authority to run docker.
   We can add one user to docker group by command:
       usermod -a -G docker xxx
