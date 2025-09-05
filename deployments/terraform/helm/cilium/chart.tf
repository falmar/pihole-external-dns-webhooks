resource "helm_release" "cilium" {
  repository = "https://helm.cilium.io/"
  chart      = "cilium"
  name       = "cilium"
  version    = "1.18.0"
  namespace  = "kube-system"
  force_update = true

  values = [file("${path.module}/values/values.yaml")]

  set = [{
    name  = "k8sServiceHost"
    value = var.k8sServiceHost
  }]

  max_history = 5
  depends_on = []
}

resource "helm_release" "extra" {
  repository = "${path.module}/charts"
  chart      = "extra"
  name       = "cilium-extra"
  version    = "0.0.0"
  namespace  = "kube-system"

  values = [file("${path.module}/values/extra.yaml")]

  max_history = 5
  depends_on = [
    helm_release.cilium
  ]
}
