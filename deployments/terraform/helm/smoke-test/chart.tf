variable "namespace" {
  type = string
}

resource "helm_release" "smoke_test" {
  chart     = "${path.module}/charts/smoke-test"
  name      = "smoke-test"
  namespace = var.namespace

  values = [file("${path.module}/values/values.yaml")]

  depends_on = []
}
