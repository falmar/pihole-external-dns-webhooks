resource "helm_release" "pihole" {
  repository = "${path.module}/charts"
  chart      = "pihole"
  name       = "main"
  version    = "0.0.0"
  namespace  = var.namespace

  values = [
    file("${path.module}/values/values.yaml"),
  ]

  set = [
    {
      name  = "secret.name"
      value = kubernetes_secret.pass.metadata[0].name
    },
    {
      name  = "secret.key"
      value = "pass"
    }
  ]

  max_history = 5
  depends_on = [
    kubernetes_secret.pass
  ]
}
