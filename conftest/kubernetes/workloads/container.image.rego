package kubernetes.container.image

import data.lib.workload

deny_latest_tag[msg] {
  workload.is_workload
	workload.containers[container]
  contains(container.image, ":latest")
	msg = sprintf("%s in the %s %s has an image, %s, using the latest tag", [container.name, workload.kind, workload.name, container.image])
}