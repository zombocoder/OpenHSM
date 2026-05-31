storage "file" { path = "/openbao/data" }

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = "true"
}

disable_mlock = true
ui            = false

# The PKCS#11 module reaches the USB-attached HSM over the network via
# openhsm-daemon (OPENHSM_ADDR env), so no USB passthrough is needed in the
# container — suitable for Docker/Kubernetes.
seal "pkcs11" {
  lib            = "/usr/local/lib/libopenhsm_pkcs11.so"
  slot           = "0"
  pin            = "123456"
  key_label      = "openbao-seal"
  hmac_key_label = "openbao-hmac"
  mechanism      = "0x1087"
  hmac_mechanism = "0x0251"
}
