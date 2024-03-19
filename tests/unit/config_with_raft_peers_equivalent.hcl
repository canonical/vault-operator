ui      = true
storage "raft" {
  path= "/vault/raft"
  node_id = "whatever-vault-k8s/0"
  # The order is different from in "config_with_raft_peers.hcl"
  retry_join {
    leader_api_addr = "https://127.0.0.2:8200"
    leader_ca_cert_file = "/path/to/ca1"
  }
   retry_join {
    leader_api_addr = "https://127.0.0.1:8200"
    leader_ca_cert_file = "/path/to/ca1"
  }

  }
listener "tcp" {
  telemetry {
    unauthenticated_metrics_access = true
  }
  address       = "[::]:8200"
  tls_cert_file = "/vault/certs/cert.pem"
  tls_key_file  = "/vault/certs/key.pem"
}
default_lease_ttl = "168h"
max_lease_ttl     = "720h"
disable_mlock     = true
cluster_addr      = "https://1.2.3.4:8201"
api_addr          = "https://1.2.3.4:8200"
telemetry {
  disable_hostname = true
  prometheus_retention_time = "12h"
}
