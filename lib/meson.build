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

lib_ver = get_option('lib_ver')
lib_dirs = get_option('lib_dirs')
inc_dirs = get_option('inc_dirs')

comm_struct_version = 'comm_struct_version.py'
pxd_version = 'clibdpdk_version.pxd'

run_command('unlink', comm_struct_version, check:false)
run_command('ln', '-s', 'comm_struct_' + lib_ver + '.py', comm_struct_version, check:true)

run_command('unlink', pxd_version, check:false)
run_command('ln', '-s', 'clibdpdk_' + lib_ver + '.pxd', pxd_version, check:true)

cmd = ['python3', 'setup.py', 'build_ext', '--inplace', '--dpdkver=' + lib_ver, '--dpdklib=' + lib_dirs, '--dpdkinc=' + inc_dirs]
run_command(cmd, check:true)
