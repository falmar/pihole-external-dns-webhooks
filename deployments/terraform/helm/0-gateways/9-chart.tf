resource "helm_release" "extra" {
  repository   = "${path.module}/charts"
  chart        = "extra"
  name         = "extra"
  version      = "0.0.0"
  namespace    = var.namespace
  force_update = true

  values = [
    file("${path.module}/values/extra.yaml"),
  ]

  max_history = 5
  depends_on  = []
}
