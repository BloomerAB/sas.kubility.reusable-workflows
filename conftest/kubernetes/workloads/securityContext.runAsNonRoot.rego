package kubernetes.securityContext.runAsNonRoot

import data.lib.workload

##########################################################################
# can be removed when running aks v1.23
#https://github.com/kubernetes/website/pull/30225
#securityContext.runAsNonRoot
deny_runAsNonRoot[msg] {
  workload.is_workload
  field := "runAsNonRoot"
  check_pods(field)
  check_containers(field)
  msg := "cannot run as root"
}

deny_runAsNonRoot[msg] {
  workload.is_workload
  workload.containers[container]
  workload.has_field(container.securityContext, "runAsNonRoot")
  container.securityContext.runAsNonRoot != true
  msg := "cannot run as root"
}

check_pods(field) {
  not input.spec.template.spec.securityContext[field]
  c := input.spec.template.spec.securityContext
  check_pod_id(c, field)
}

check_pod_id(c, field) {
  not workload.has_field(c, field)
}

check_pod_id(c, field) {
  c[field] != true
}

check_containers(field) {
  workload.containers[container]
  check_container_id(container, field)
}

check_container_id(container, field) {
  container.securityContext[field] != true
}

check_container_id(container, field) {
  not workload.has_field(container.securityContext, field)
}
