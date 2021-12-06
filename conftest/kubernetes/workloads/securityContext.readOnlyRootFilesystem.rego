package kubernetes.securityContext.readOnlyRootFilesystem

import data.lib.workload

deny_readOnlyRootFilesystem[msg] {
  workload.is_workload
  workload.containers[container]
  not container.securityContext.readOnlyRootFilesystem
  msg = sprintf("%s: %s, containers must have securityContext with readOnlyRootFilesystem: true", [workload.kind, workload.name])
}
