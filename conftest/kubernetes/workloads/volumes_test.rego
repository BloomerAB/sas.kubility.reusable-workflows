package kubernetes.volumes

test_regular_volume_allowed {
  count(deny) == 0 with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
      volumes:
      - name: volume
        hostPath:
          path: /some/okay/volume
`)
}

test_docker_sock_volume_not_allowed {
  deny != set() with input as yaml.unmarshal(`
kind: Deployment
metadata:
  name: test
spec:
  template:
    spec:
      containers:
        - name: first-container
      volumes:
      - name: docker-sock-volume
        hostPath:
          path: /var/run/docker.sock
`)
}
