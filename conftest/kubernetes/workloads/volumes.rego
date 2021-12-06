package kubernetes.volumes

import data.lib.workload

# https://kubesec.io/basics/spec-volumes-hostpath-path-var-run-docker-sock/
deny[msg] {
	volume = input.spec.template.spec.volumes[_]
  contains(volume.hostPath.path, "/var/run/docker.sock")
  msg = sprintf("%s %s is mounting the Docker socket", [workload.kind, workload.name])
}
