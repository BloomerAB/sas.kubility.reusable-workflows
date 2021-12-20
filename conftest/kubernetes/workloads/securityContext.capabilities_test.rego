package kubernetes.securityContext.capabilities

test_container_with_drop_all_capabilites_should_pass {
  count(deny_any_privileges) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            capabilities:
              drop:
                - all
        - name: privileged-container
          securityContext:
            capabilities:
              drop:
                - all
`)
}

test_container_with_drop_all_capabilites_as_case_insensitive_should_pass {
  count(deny_any_privileges) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            capabilities:
              drop:
                - all
        - name: privileged-container
          securityContext:
            capabilities:
              drop:
                - ALL
`)
}

test_container_without_drop_all_capabilites_should_pass {
  count(deny_any_privileges) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            capabilities:
              drop:
                - all
        - name: privileged-container
          securityContext:
`)
}
