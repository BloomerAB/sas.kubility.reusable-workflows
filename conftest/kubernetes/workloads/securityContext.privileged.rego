package kubernetes.securityContext.privileged

import data.lib.workload

deny_privileged_container[msg] {
  workload.is_workload
  workload.containers[container]
  container.securityContext.privileged == true
  msg = sprintf("%s: %s, containers are not allowed to have securityContext with privileged: true %s", [workload.kind, workload.name, container.name])
}
