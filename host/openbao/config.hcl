storage "file" { path = "./data" }

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = "true"
}

disable_mlock = true
ui            = true

seal "pkcs11" {
  lib            = "/Users/zombocoder/dev/zombocoder/OpenHSM/host/pkcs11/build/libopenhsm_pkcs11.dylib"
  slot           = "0"
  pin            = "123456"
  key_label      = "openbao-seal"
  hmac_key_label = "openbao-hmac"
  mechanism      = "0x1087"
  hmac_mechanism = "0x0251"
  generate_key   = "true"
}
