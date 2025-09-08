
resource "helm_release" "external_dns_pihole" {
  repository = "https://kubernetes-sigs.github.io/external-dns"
  chart      = "external-dns"
  name       = "external-dns-pihole"
  version    = "1.18.0"
  namespace  = var.namespace

  values = [
    file("${path.module}/values/values.yaml")
  ]

  max_history = 5
  depends_on  = [
    kubernetes_secret.pass
  ]
}
