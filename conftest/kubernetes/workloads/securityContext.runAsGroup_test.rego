package kubernetes.securityContext.runAsGroup

test_runAsGroup_defined_on_pod_and_all_containers_should_pass {
  count(deny_runAsGroup) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        runAsGroup: 1000
      containers:
        - name: first-container
          securityContext:
            runAsGroup: 1000
        - name: privileged-container
          securityContext:
            runAsGroup: 1000
`)
}

test_runAsGroup_defined_on_all_containers_should_pass {
  count(deny_runAsGroup) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            runAsGroup: 1000
        - name: privileged-container
          securityContext:
            runAsGroup: 1000
`)
}

test_runAsGroup_defined_on_pod_and_some_containers_should_pass {
  count(deny_runAsGroup) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        runAsGroup: 1000
      containers:
        - name: first-container
          securityContext:
            runAsGroup: 1000
        - name: privileged-container
`)
}

test_runAsGroup_defined_on_pod_should_pass {
  count(deny_runAsGroup) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        runAsGroup: 1000
      containers:
        - name: first-container
          securityContext:
        - name: privileged-container
          securityContext:
`)
}

test_runAsGroup_defined_on_pod_with_low_id_and_all_containers_should_pass {
  count(deny_runAsGroup) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        runAsGroup: 999
      containers:
        - name: first-container
          securityContext:
            runAsGroup: 1000
        - name: privileged-container
          securityContext:
            runAsGroup: 1000
`)
}

test_runAsGroup_only_defined_on_some_container {
  count(deny_runAsGroup) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
      containers:
        - name: first-container
          securityContext:
        - name: privileged-container
          securityContext:
`)
}

test_runAsGroup_defined_on_some_container_should_not_pass {
  count(deny_runAsGroup) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
      containers:
        - name: first-container
          securityContext:
            runAsGroup: 1000
        - name: privileged-container
          securityContext:
`)
}

test_runAsGroup_defined_on_all_containers_with_low_id_on_some_should_not_pass {
  count(deny_runAsGroup) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
      containers:
        - name: first-container
          securityContext:
            runAsGroup: 1000
        - name: privileged-container
          securityContext:
            runAsGroup: 999
`)
}

test_runAsGroup_defined_on_pod_and_all_containers_with_low_id_on_some_container_should_not_pass {
  count(deny_runAsGroup) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        runAsGroup: 1000
      containers:
        - name: first-container
          securityContext:
            runAsGroup: 1000
        - name: privileged-container
          securityContext:
            runAsGroup: 999
`)
}
