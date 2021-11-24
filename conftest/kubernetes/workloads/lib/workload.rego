package lib.workload

kind := input.kind
name := input.metadata.name

lowest_allowed_id := 1000

has_field(x, k) {
  _ = x[k]
}

is_workload {
  kind = "Statefulset"
}

is_workload {
  kind = "Deployment"
}

is_workload {
  kind = "DaemonSet"
}

pod_containers(pod) = all_containers {
  keys = {"containers", "initContainers"}
  all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

containers[container] {
  all_containers = pod_containers(input.spec.template)
  container = all_containers[_]
}

split_image(image) = [image, "latest"] {
  contains(image, ":latest")
}