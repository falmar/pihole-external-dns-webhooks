# critical

resource "kubernetes_namespace_v1" "gateways" {
  metadata {
    name = "gateways"
  }
}

resource "helm_release" "cert_manager_crds" {
  repository = "${path.root}/helm/cert-manager/charts"
  chart      = "crds"
  name       = "cert-manager-crds"
  version    = "0.0.0"
  namespace  = "default"

  force_update = true

  values = []

  max_history = 5
  depends_on  = []
}
resource "helm_release" "gateways_crds" {
  repository = "${path.root}/helm/0-gateways/charts"
  chart      = "crds"
  name       = "gateway-api-crds"
  version    = "0.0.0"
  namespace  = "default"
  force_update = true

  values = []

  max_history = 5
  depends_on = []
}

module "helm_cilium" {
  source = "./helm/cilium"

  k8sServiceHost = "${var.cluster_name}-control-plane"

  depends_on = [
    helm_release.gateways_crds,
    helm_release.cert_manager_crds
  ]
}

module "helm_gateways" {
  source = "./helm/0-gateways"

  namespace = kubernetes_namespace_v1.gateways.metadata[0].name

  depends_on = [
    helm_release.cert_manager_crds,
    module.helm_cilium
  ]
}


resource "kubernetes_namespace_v1" "cert_manager" {
  metadata {
    name = "cert-manager"
  }
}

module "helm_cert_manager" {
  source = "./helm/cert-manager"

  depends_on = [
    module.helm_cilium,
    kubernetes_namespace_v1.cert_manager
  ]
}


resource "kubernetes_namespace_v1" "pihole" {
  metadata {
    name = "pihole-system"
  }
}
module "helm_pihole" {
  source = "./helm/pihole"

  namespace = kubernetes_namespace_v1.pihole.metadata[0].name

  depends_on = [
    module.helm_cilium,
    kubernetes_namespace_v1.pihole
  ]
}

resource "kubernetes_namespace_v1" "external_dns" {
  metadata {
    name = "external-dns"
  }
}
module "helm_external_dns" {
  source = "./helm/external-dns"

  namespace = kubernetes_namespace_v1.external_dns.metadata[0].name

  depends_on = [
    module.helm_cilium,
    module.helm_pihole,
    kubernetes_namespace_v1.external_dns
  ]
}
