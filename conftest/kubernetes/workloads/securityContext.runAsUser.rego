package kubernetes.securityContext.runAsUser

import data.lib.workload
import data.lib.permissions

min_allowed_id := 1000

deny_runAsUser[msg] {
  workload.is_workload
  field := "runAsUser"
  permissions.check_pods(field)
  permissions.check_containers(field)
  msg := sprintf("%s: %s, pod or all containers must have a runAsUser defined with value above %v", [workload.kind, workload.name, min_allowed_id])
}

deny_runAsUser[msg] {
  workload.is_workload
  workload.containers[container]
  workload.has_field(container.securityContext, "runAsUser")
  container.securityContext.runAsUser < min_allowed_id
  msg := sprintf("%s: %s, pod or all containers must have a runAsUser defined with value above %v", [workload.kind, workload.name, min_allowed_id])
}
