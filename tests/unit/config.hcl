ui      = true
storage "raft" {
  path= "/var/snap/vault/common/raft"
  node_id = "whatever-vault/0"
}
listener "tcp" {
  telemetry {
    unauthenticated_metrics_access = true
  }
  address       = "[::]:8200"
}
default_lease_ttl = "168h"
max_lease_ttl     = "720h"
disable_mlock     = true
cluster_addr      = "https://1.2.1.2:8201"
api_addr          = "https://1.2.1.2:8200"
telemetry {
  disable_hostname = true
  prometheus_retention_time = "12h"
}
