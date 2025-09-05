resource "kubernetes_secret" "pass" {
  metadata {
    name      = "pihole-pass"
    namespace = var.namespace
  }

  data = {
    pass = "kind-cluster",
  }
}
