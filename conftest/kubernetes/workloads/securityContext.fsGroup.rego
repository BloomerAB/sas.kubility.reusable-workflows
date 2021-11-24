package kubernetes.securityContext.fsGroup

import data.lib.workload

min_allowed_fsGroup_id := 2

deny_fsGroup[msg] {
  workload.is_workload
  fsGroup
  msg = sprintf("%s: %s, pod must have a fsGroup defined with value above %v", [input.kind, input.metadata.name, min_allowed_fsGroup_id])
}

fsGroup {
  c := input.spec.template.spec.securityContext
  field := "fsGroup"
  not workload.has_field(c, field)
}

fsGroup {
  input.spec.template.spec.securityContext.fsGroup > min_allowed_fsGroup_id
}
