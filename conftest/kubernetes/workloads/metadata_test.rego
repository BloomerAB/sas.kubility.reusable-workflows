package kubernetes.metadata

test_metadata_without_name_should_not_pass {
    count(deny) != 0 with input as yaml.unmarshal(`
kind: Deployment
`)
}
