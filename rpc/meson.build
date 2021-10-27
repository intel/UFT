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

#protoc = find_program('protoc')
protoc = find_program('python3')
spec = 'umd.proto'

in_dir = meson.current_source_dir()
out_dir = meson.current_build_dir()

custom_target('py_ct',
  output: ['umd_pb2.py', 'umd_pb2_grpc.py'],
  command : [protoc,
            '-m',
            'grpc_tools.protoc',
            '-I' + in_dir,
            '--python_out=' + out_dir,
	          '--grpc_python_out=' + out_dir,
            spec],
  depend_files : spec,
  build_by_default : true
)

# protoc_plugin = find_program('grpc_python_plugin')
# custom_target('grpc_ct',
#   output: 'umd_pb2_grpc.py',
#   command : [protoc, '-I' + in_dir, '--python_out=' + out_dir,
#             '--grpc_out=' + out_dir,
#             '--plugin=protoc-gen-grpc=' + protoc_plugin.path(), spec],
#   depend_files : spec,
#   build_by_default : true
#)
