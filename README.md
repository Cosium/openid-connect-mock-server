# openid-connect-mock-server

OpenID connect mock server written in java 8

### Keystore

`keystore.pkcs12` was built using:

```
keytool -genkeypair -keystore keystore.pkcs12 -storetype pkcs12 -storepass changeit -keyalg RSA -keysize 2048 -alias oidcserver -keypass changeit -sigalg SHA256withRSA
```