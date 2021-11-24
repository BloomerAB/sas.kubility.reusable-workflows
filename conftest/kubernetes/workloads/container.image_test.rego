package kubernetes.container.image

test_no_image_with_latest_tag_should_pass {
  count(warn_latest_tag) == 0 with input as yaml.unmarshal(`
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

test_one_latest_tag_should_not_pass {
  count(warn_latest_tag) != 0 with input as yaml.unmarshal(`
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

test_one_container_with_latest_tag_and_one_container_without_should_not_pass {
  count(warn_latest_tag) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: container-name
          image: flysas
        - name: container-name
          image: flysas:latest
`)
}

test_one_image_from_trusted_registry_should_pass {
  count(warn_unknown_image_prefix) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          image: okay-source
`)
}

test_one_image_from_untrusted_registry_should_not_pass {
  count(warn_unknown_image_prefix) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          image: not-okay-registry
`)
}

test_several_images_from_untrusted_registries_should_not_pass {
  count(warn_unknown_image_prefix) != 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
          image: organisation-myApp
        - name: second-container
          image: not-okay-registry:some-version
`)
}