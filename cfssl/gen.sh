cfssl gencert \
  -ca ca.crt \
  -ca-key ca.key \
  mutating-csr.json | cfssljson -bare tls

mv tls-key.pem tls.key
mv tls.pem tls.crt
rm tls.csr
