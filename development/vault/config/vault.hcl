ui = true

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1  # TODO: Enable TLS in production!
}

api_addr = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"

# Disable mlock for dev mode (enable in production)
disable_mlock = true

# Log level
log_level = "info"
