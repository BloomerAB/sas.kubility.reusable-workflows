package kubernetes.securityContext.runAsGroup

import data.lib.workload
import data.lib.permissions

min_allowed_id := 1000

deny_runAsGroup[msg] {
  workload.is_workload
  field := "runAsGroup"
  permissions.check_pods(field)
  permissions.check_containers(field)
  msg := sprintf("%s: %s, pod or all containers must have a runAsGroup defined with value above %v", [workload.kind, workload.name, min_allowed_id])
}

deny_runAsGroup[msg] {
  workload.is_workload
  workload.containers[container]
  workload.has_field(container.securityContext, "runAsGroup")
  container.securityContext.runAsGroup < 1000
  msg := sprintf("%s: %s, pod or all containers must have a runAsGroup defined with value above %v", [workload.kind, workload.name, min_allowed_id])
}
