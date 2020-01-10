package com.cosium.openid_connect.mock.server;

import io.vertx.core.http.HttpServerRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** @author Réda Housni Alaoui */
class ClientBasicAuthentication {
  final String clientId;
  final String clientSecret;

  ClientBasicAuthentication(HttpServerRequest request) {
    String authorizationHeader = request.getHeader("Authorization");

    String base64BasicAuthenticationToken;
    if (authorizationHeader == null) {
      base64BasicAuthenticationToken = "";
    } else {
      base64BasicAuthenticationToken = authorizationHeader.substring("Basic ".length());
    }

    String[] basicAuthenticationToken =
        new String(
                Base64.getDecoder().decode(base64BasicAuthenticationToken), StandardCharsets.UTF_8)
            .split(":");

    if (basicAuthenticationToken.length != 2) {
      clientId = null;
      clientSecret = null;
    } else {
      clientId = basicAuthenticationToken[0];
      clientSecret = basicAuthenticationToken[1];
    }
  }

  boolean isComplete() {
    return clientId != null && clientSecret != null;
  }
}
