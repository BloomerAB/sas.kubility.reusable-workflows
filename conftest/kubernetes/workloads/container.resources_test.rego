package kubernetes.resources

test_cpu_limit_not_defined_should_not_pass {
  count(deny_no_cpu_limit) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: container-name
          resources:
            requests:
              cpu: 200m
              memory: 1Gi
            limits:
              memory: 1Gi
`)
}

test_memory_limit_not_defined_should_not_pass {
  count(deny_no_memory_limit) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: container-name
          resources:
            requests:
              cpu: 200m
              memory: 1Gi
            limits:
              cpu: 200m
`)
}

test_cpu_request_not_defined_should_not_pass {
  count(deny_no_cpu_request) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: container-name
          resources:
            requests:
              memory: 1Gi
            limits:
              cpu: 200m
              memory: 1Gi
`)
}

test_memory_request_not_defined_should_not_pass {
  count(deny_no_memory_request) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: container-name
          resources:
            requests:
              cpu: 200m
            limits:
              cpu: 200m
              memory: 1Gi
`)
}