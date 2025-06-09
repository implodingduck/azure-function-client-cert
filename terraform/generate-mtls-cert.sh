openssl genrsa -out root.key 2048
openssl req -x509 -new -nodes -key root.key -sha256 -days 1024 -out root.crt -subj "/C=US/ST=North Dakota/L=Fargo/O=Implodingduck/CN=implodingduck-root"
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/C=US/ST=North Dakota/L=Fargo/O=Implodingduck/CN=implodingduck-client"
openssl x509 -req -in client.csr -CA root.crt -CAkey root.key -CAcreateserial -out client.crt -days 1024 -sha256

openssl pkcs12 -export -out root.pfx -inkey root.key -in root.crt -name "Implodingduck Root CA"