package kubernetes.container.probe

import data.lib.workload

test_livenessProbe_not_defined_should_warn {
  count(warn_no_livenessprobe) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: container-name
`)
}

test_readinessProbe_not_defined_should_warn {
  count(warn_no_readinessprobe) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: container-name
`)
}
