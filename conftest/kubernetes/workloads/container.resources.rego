package kubernetes.resources

import data.lib.workload

deny_no_cpu_limit[msg] {
  workload.is_workload
	workload.containers[container]
  not container.resources.limits.cpu
  msg = sprintf("All containers in %s %s must set resources.limits.cpu", [workload.kind, workload.name])
}

deny_no_memory_limit[msg] {
  workload.is_workload
	workload.containers[container]
  not container.resources.limits.memory
  msg = sprintf("All containers in %s %s must set resources.limits.memory", [workload.kind, workload.name])
}

deny_no_cpu_request[msg] {
  workload.is_workload
	workload.containers[container]
  not container.resources.requests.cpu
  msg = sprintf("All containers in %s %s must set resources.requests.cpu", [workload.kind, workload.name])
}

deny_no_memory_request[msg] {
  workload.is_workload
	workload.containers[container]
  not container.resources.requests.memory
  msg = sprintf("All containers in %s %s must set resources.requests.memory", [workload.kind, workload.name])
}
