[![Travis branch](https://img.shields.io/travis/Cosium/openid-connect-mock-server/master.svg)](https://travis-ci.org/Cosium/openid-connect-mock-server)

[![Maven Central 1.10.x](https://img.shields.io/maven-central/v/com.cosium.openid_connect/openid-connect-mock-server/1.10.svg)](https://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22com.cosium.openid_connect%22%20AND%20a%3A%22openid-connect-mock-server%22)

# openid-connect-mock-server

OpenID connect mock server written in java 8

### Keystore

`keystore.pkcs12` was built using:

```
keytool -genkeypair -keystore keystore.pkcs12 -storetype pkcs12 -storepass changeit -keyalg RSA -keysize 2048 -alias oidcserver -keypass changeit -sigalg SHA256withRSA
```