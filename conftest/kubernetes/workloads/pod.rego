package kubernetes.pod

deny[msg] {
  input.kind == "Pod"
  msg = "Manifest kind: Pod not allowed"
}
