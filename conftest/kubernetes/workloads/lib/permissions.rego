package lib.permissions

import data.lib.workload

check_pods(field) {
  not input.spec.template.spec.securityContext[field]
  c := input.spec.template.spec.securityContext
  check_pod_id(c, field)
}

check_pod_id(c, field) {
  not workload.has_field(c, field)
}

check_pod_id(c, field) {
  c[field] < workload.lowest_allowed_id
}

check_containers(field) {
  workload.containers[container]
  check_container_id(container, field)
}

check_container_id(container, field) {
  container.securityContext[field] < workload.lowest_allowed_id
}

check_container_id(container, field) {
  not workload.has_field(container.securityContext, field)
}
