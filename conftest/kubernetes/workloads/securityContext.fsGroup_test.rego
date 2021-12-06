package kubernetes.securityContext.fsGroup

test_fsGroup_with_low_id_should_pass {
  count(deny_fsGroup) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        fsGroup: 1
`)
}

test_fsGroup_with_too_high_id_should_not_pass {
  count(deny_fsGroup) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
        fsGroup: 4
`)
}

test_fsGroup_not_defined_should_not_pass {
  count(deny_fsGroup) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      securityContext:
`)
}
