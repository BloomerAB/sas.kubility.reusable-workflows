package kubernetes.securityContext.readOnlyRootFilesystem

test_readOnlyRootFilesystem_true_for_all_containers_should_pass {
  count(deny_readOnlyRootFilesystem) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            readOnlyRootFilesystem: true
        - name: privileged-container
          securityContext:
            readOnlyRootFilesystem: true
`)
}

test_readOnlyRootFilesystem_false_for_some_containers_should_not_pass {
  count(deny_readOnlyRootFilesystem) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            readOnlyRootFilesystem: true
        - name: privileged-container
          securityContext:
            readOnlyRootFilesystem: false
`)
}

test_readOnlyRootFilesystem_not_defined_for_some_containers_should_not_pass {
  count(deny_readOnlyRootFilesystem) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            readOnlyRootFilesystem: true
        - name: privileged-container
          securityContext:
`)
}
