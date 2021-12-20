package kubernetes.securityContext.capabilities

import data.lib.workload

deny_any_privileges[msg] {
  workload.is_workload
  workload.containers[container]
  not drop_all_capabilities(container, "all")
  msg = sprintf("%s: %s, containers must drop all capabilities", [workload.kind, workload.name])
}

drop_all_capabilities(container, capability) {
  lower(container.securityContext.capabilities.drop[_]) == capability
}
