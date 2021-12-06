package kubernetes.network

test_hostAliases_defined_should_not_pass {
    count(deny_hostAliases) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      hostAliases:
`)
}

test_hostIPC_defined_should_not_pass {
    count(deny_hostIPC) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      hostIPC:
`)
}
test_hostNetwork_defined_should_not_pass {
    count(deny_hostNetwork) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      hostNetwork:
`)
}
test_hostPID_defined_should_not_pass {
    count(deny_hostPID) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      hostPID:
`)
}
