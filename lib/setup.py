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
#
from distutils.core import setup, Extension
from Cython.Build import cythonize
import sys, argparse

libs = [
    ':librte_eal.so',
    ':librte_ethdev.so'
]
lib_dirs = ['/usr/local/lib']
inc_dirs = ['/usr/local/include']
lib_ver = ['v22.03']

parser = argparse.ArgumentParser(add_help = False)
parser.add_argument('--dpdklib', action = 'append')
parser.add_argument('--dpdkinc', action = 'append')
parser.add_argument('--dpdkver', action = 'append')
args, left = parser.parse_known_args()

if args.dpdklib:
    lib_dirs = args.dpdklib
    print('DPDK lib: %s' % lib_dirs)

if args.dpdkinc:
    inc_dirs = args.dpdkinc
    print('DPDK inc: %s' % inc_dirs)

if args.dpdkver:
    lib_ver = args.dpdkver
    print('DPDK ver: %s' % lib_ver)

if '-h' in sys.argv or '--help' in sys.argv:
    print('''DPDK options:
  --dpdklib           Specify the DPDK libraries directory
                      [default: /usr/local/lib]
  --dpdkinc           Specify the DPDK included files directory
                      [default: /usr/local/include]
  --dpdkver           Specify the DPDK version
                      [default: v22.03]
''')

sys.argv = sys.argv[:1] + left

kwarg = {"build_dir" : "."}
setup(
    ext_modules = cythonize(
        Extension(
            'dpdk',
            sources=['wrapper.pyx'],
            language='c',
            include_dirs=inc_dirs,
            library_dirs=lib_dirs,
            libraries=libs,
            # extra_compile_args=['-march=corei7'],
            extra_link_args=[]
        ),
        compiler_directives={'language_level' : "3"},
        compile_time_env={'DPDK_VERSION': lib_ver[0]},
        **kwarg
    )
)
