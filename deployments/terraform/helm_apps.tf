resource "kubernetes_namespace_v1" "smoke_test" {
  metadata {
    name = "smoke-test"
  }
}
module "helm_smoke_test" {
  source = "./helm/smoke-test"

  namespace = kubernetes_namespace_v1.smoke_test.metadata[0].name

  depends_on = [
    helm_release.cert_manager_crds,
    module.helm_cilium
  ]
}
