package kubernetes.container.image

test_no_latest_tag_should_pass {
  count(deny_latest_tag) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          image: ok-container-image
`)
}

test_latest_tag_should_not_pass {
  count(deny_latest_tag) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: container-name
          image: flysas:latest
`)
}
