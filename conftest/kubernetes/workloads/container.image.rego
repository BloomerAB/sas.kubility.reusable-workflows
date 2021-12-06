package kubernetes.container.image

import data.lib.workload

known_sources := {"okay-source"}

warn_latest_tag[msg] {
  container := workload.containers[i]
  image_prefix := split(container.image, ":")[1]
  image_prefix == "latest"
  msg = sprintf("Container: %s, in %s: %s, is using Image: %s, with tag latest", [container.name, workload.kind, workload.name, container.image])
}

warn_unknown_image_prefix[msg] {
  container := workload.containers[i]
  image_prefix := split(container.image, ":")[0]
  not workload.has_field(known_sources, image_prefix)
  msg = sprintf("Container: %s, in %s %s has an Image: %s, that comes from an unknown source", [container.name, workload.kind, container.image, workload.name])
}
