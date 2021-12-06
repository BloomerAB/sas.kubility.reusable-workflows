package kubernetes.container.probe

import data.lib.workload

warn_no_livenessprobe[msg] {
  workload.containers[container]
  not container.livenessProbe
  msg := sprintf("%s %s has containers without livenessProbe", [workload.kind, workload.name])
}

warn_no_readinessprobe[msg] {
  workload.containers[container]
  not container.readinessProbe
  msg := sprintf("%s %s has containers without readinessProbe", [workload.kind, workload.name])
}