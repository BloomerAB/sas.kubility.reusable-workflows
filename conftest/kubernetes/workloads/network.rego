package kubernetes.network

import data.lib.workload

pod := input.spec.template.spec

# https://kubesec.io/basics/spec-hostaliases/
deny_hostAliases[msg] {
  workload.is_workload
  pod.hostAliases
  msg = sprintf("The %s %s is managing host aliases", [workload.kind, workload.name])
}

# https://kubesec.io/basics/spec-hostipc/
deny_hostIPC[msg] {
  workload.is_workload
  pod.hostIPC
  msg = sprintf("%s %s is sharing the host IPC namespace", [workload.kind, workload.name])
}

# https://kubesec.io/basics/spec-hostnetwork/
deny_hostNetwork[msg] {
  workload.is_workload
  pod.hostNetwork
  msg = sprintf("The %s %s is connected to the host network", [workload.kind, workload.name])
}

# https://kubesec.io/basics/spec-hostpid/
deny_hostPID[msg] {
  workload.is_workload
  pod.hostPID
  msg = sprintf("The %s %s is sharing the host PID", [workload.kind, workload.name])
}
