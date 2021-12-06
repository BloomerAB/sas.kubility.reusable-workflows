package kubernetes.securityContext.allowPrivilegeEscalation

import data.lib.workload

deny_allowPrivilegeEscalation[msg] {
  workload.is_workload
  allowPrivilegeEscalation
  msg = sprintf("%s: %s, containers must have securityContext with allowPrivilegeEscalation: false", [input.kind, input.metadata.name])
}

allowPrivilegeEscalation {
  workload.containers[container]
  not workload.has_field(container.securityContext, "allowPrivilegeEscalation")
}

allowPrivilegeEscalation {
  workload.containers[container]
  container.securityContext.allowPrivilegeEscalation == true
}
