resource "helm_release" "cert_manager" {
  repository = "https://charts.jetstack.io"
  chart      = "cert-manager"
  name       = "cert-manager"
  version    = "1.17.2"
  namespace  = "cert-manager"
  skip_crds  = true

  values = [file("${path.module}/values/values.yaml")]

  max_history = 5
  depends_on  = []
}

resource "helm_release" "extra" {
  repository = "${path.module}/charts"
  chart      = "extra"
  name       = "extra"
  version    = "0.0.0"
  namespace  = "cert-manager"

  values = [
    file("${path.module}/values/extra.yaml"),
  ]

  max_history = 5
  depends_on = [
    helm_release.cert_manager
  ]
}
