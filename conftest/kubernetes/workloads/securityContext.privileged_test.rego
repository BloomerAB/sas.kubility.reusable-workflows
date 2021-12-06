package kubernetes.securityContext.privileged

import data.lib.workload

test_privileged_false_for_all_containers_should_pass {
  count(deny_privileged_container) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            privileged: false
        - name: privileged-container
          securityContext:
            privileged: false
`)
}

test_privileged_not_defined_for_any_container_should_pass {
  count(deny_privileged_container) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
        - name: privileged-container
          securityContext:
`)
}

test_privileged_true_for_some_containers_should_not_pass {
  count(deny_privileged_container) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            privileged: false
        - name: privileged-container
          securityContext:
            privileged: true
`)
}
