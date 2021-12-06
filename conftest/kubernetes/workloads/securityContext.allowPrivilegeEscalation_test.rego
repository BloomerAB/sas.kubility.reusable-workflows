package kubernetes.securityContext.allowPrivilegeEscalation

import data.lib.kubernetes

test_privilegeEscalation_false_for_all_containers_should_pass {
  count(deny_allowPrivilegeEscalation) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            allowPrivilegeEscalation: false
        - name: privileged-container
          securityContext:
            allowPrivilegeEscalation: false
`)
}

test_privilege_escalation_true_for_some_containers_should_not_pass {
  count(deny_allowPrivilegeEscalation) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            allowPrivilegeEscalation: false
        - name: privileged-container
          securityContext:
            allowPrivilegeEscalation: true
`)
}

test_privilege_escalation_defined_on_some_containers_should_not_pass {
  count(deny_allowPrivilegeEscalation) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          securityContext:
            allowPrivilegeEscalation: false
        - name: privileged-container
          securityContext:
`)
}
