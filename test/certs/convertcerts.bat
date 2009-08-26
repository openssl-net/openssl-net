C:\OpenSSL\bin\openssl pkcs12 -export -aes128 -in /source/misc/privatekey_test/bin/debug/certs/client.crt -inkey /source/misc/privatekey_test/bin/debug/certs/client.key -out /source/misc/privatekey_test/bin/debug/certs/client.pfx
C:\OpenSSL\bin\openssl pkcs12 -export -aes128 -in /source/misc/privatekey_test/bin/debug/certs/server.crt -inkey /source/misc/privatekey_test/bin/debug/certs/server.key -out /source/misc/privatekey_test/bin/debug/certs/server.pfx
C:\OpenSSL\bin\openssl crl2pkcs7 -nocrl -certfile /source/misc/privatekey_test/bin/debug/certs/ca_chain.pem -outform DER -out /source/misc/privatekey_test/bin/debug/certs/ca_chain.p7c
copy ca.crt ca_chain.pem
