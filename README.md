# jwt-go signing and verifying example

## creating a new pair of RSA key files

```bash
$ ssh-keygen -t rsa -b 4096 -m pem -f ./secrets/rsa
$ ssh-keygen -f ./secrets/rsa.pub -e -m pkcs8 > ./secrets/rsa.pub.pkcs8
```