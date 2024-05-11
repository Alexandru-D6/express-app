```
    openssl ca -config openssl.cnf [-policy policy_to_use] -extensions eapserver_ext -extfile msextensions -in certreq.pem -out serverCert.pem
```
https://www.cockroachlabs.com/docs/stable/create-security-certificates-openssl#step-3-create-the-certificate-and-key-pair-for-the-first-user


openssl genrsa -out radius.key 4096
openssl req -new -x509 -config ca.cnf -key radius.key -days 365 -out radiusCA.pem -batch
rm -f index.txt serial.txt
touch index.txt
echo '01' > serial.txt

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out serverReq.pem
openssl ca -config server.cnf -extensions eapserver_ext -extfile msextensions -in serverReq.pem -out serverCert.pem