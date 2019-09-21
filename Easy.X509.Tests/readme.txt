
The below generated "certificate.pfx" is built for test purpose only, it will
be read directly from its pfx file container. You do not have to register it in
your system.

--------------------------------------------------------------------------------------------
Create a file 'x509.ext'
--------------------------------------------------------------------------------------------
[ ca ]
# X509 extensions for a ca
keyUsage                = critical, cRLSign, keyCertSign
basicConstraints        = CA:TRUE, pathlen:0
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer:always

[ server ]
# X509 extensions for a server
keyUsage                = critical,digitalSignature,keyEncipherment
extendedKeyUsage        = serverAuth,clientAuth
basicConstraints        = critical,CA:FALSE
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid,issuer:always

--------------------------------------------------------------------------------------------
Create a CA key, a certificate request and the test certificate validated by the CA
--------------------------------------------------------------------------------------------
$ openssl req -new -sha256 -nodes -newkey rsa:2048 -keyout CA.key -out CA.csr
$ openssl x509 -req -sha256 -extfile x509.ext -extensions ca -in CA.csr -signkey CA.key -days 1095 -out CA.pem
$ openssl req -new -sha256 -nodes -newkey rsa:4096 -keyout test-private.key -out test-certificate-signing-request.csr
$ openssl x509 -req -sha256 -CA CA.pem -CAkey CA.key -days 730 -CAcreateserial -CAserial CA.srl -extfile x509.ext -extensions server -in test-certificate-signing-request.csr -out test-certificate.pem

--------------------------------------------------------------------------------------------
Create pfx container
--------------------------------------------------------------------------------------------
$ openssl pkcs12 -export -out certificate.pfx -inkey test-private.key -in test-certificate.pem -certfile CA.pem
