
lib_ver = get_option('lib_ver')
flow_ver = 'flow_version.proto'
protos = [
	'flow.proto',
	'qos.proto',
	flow_ver,
]

run_command('unlink', flow_ver, check:false)
run_command('ln', '-s', 'flow_' + lib_ver + '.proto', flow_ver,check:true)

foreach p:protos
	run_command('python3','-m' ,'grpc_tools.protoc', '-I./', '--python_out=.', '--grpc_python_out=.', p, check:true)
endforeach
