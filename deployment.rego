package main
deny[msg] {
 input.kind == "Deployment"
 not input.spec.template.spec.securityContext.runAsNonRoot
 msg := "Containers must not run as root"
}
deny[msg] {
input.kind == "Deployment"
  image := input.spec.template.spec.containers[_].image
  not startswith(image, "myorg.com/")
  msg := sprintf("image '%v' doesn't come from myorg.com repository", [image])
}