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

DPDK_NAME = dpdk-shared-lib
DPDK_TAG = v21.08
IMAGE_NAME = ${DPDK_NAME}:${DPDK_TAG}
DCF_NAME = dcf-tool
DCF_IMAGE_NAME = ${DCF_NAME}:${DPDK_TAG}

# To pass proxy for docker build from env invoke make with make image-<IMAGE> HTTP_PROXY=$http_proxy HTTPs_PROXY=$https_proxy
DOCKERARGS?=
ifdef HTTP_PROXY
	DOCKERARGS += --build-arg http_proxy=$(HTTP_PROXY)
endif
ifdef HTTPS_PROXY
	DOCKERARGS += --build-arg https_proxy=$(HTTPS_PROXY)
endif


# Build dcf-tool docker image
dcf-image: images/Dockerfile.uft; $(info Building dcf docker image...)
	docker build -t $(DCF_IMAGE_NAME) -f images/Dockerfile.uft . --build-arg DPDK_TAG=$(DPDK_TAG) $(DOCKERARGS)

.PHONY: dcf-image
