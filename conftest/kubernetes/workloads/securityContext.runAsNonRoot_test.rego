package kubernetes.securityContext.runAsNonRoot

test_runAsNonRoot_defined_everywhere {
  count(deny_runAsNonRoot) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: first-container
          securityContext:
            runAsNonRoot: true
        - name: privileged-container
          securityContext:
            runAsNonRoot: true
`)
}

## kör på den här
# test_runAsNonRoot_defined_on_pod_and_some_containers_should_pass {
test_runAsRoot_not_defined_on_one_container {
  count(deny_runAsNonRoot) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: first-container
          securityContext:
            runAsNonRoot: true
        - name: privileged-container
          securityContext:
`)
}

test_runAsNonRoot_defined_on_pod_and_some_containers {
  count(deny_runAsNonRoot) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: first-container
          securityContext:
            runAsNonRoot: true
        - name: privileged-container
          securityContext:
`)
}

test_runAsNonRoot {
  count(deny_runAsNonRoot) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: false
      containers:
        - name: first-container
          securityContext:
            runAsNonRoot: true
        - name: privileged-container
          securityContext:
            runAsNonRoot: true
`)
}

test_one_container_allows_runAsNonRoot {
  count(deny_runAsNonRoot) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: first-container
          securityContext:
            runAsNonRoot: true
        - name: privileged-container
          securityContext:
            runAsNonRoot: false
`)
}

test_runAsNonRoot_not_defined_for_all_containers {
  count(deny_runAsNonRoot) != 0 with input as yaml.unmarshal(`
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
            runAsNonRoot: true
        - name: privileged-container
          securityContext:
`)
}