package kubernetes.metadata

deny[msg] {
  not input.metadata.name
  msg = "All manifests must include metadata.name"
}
