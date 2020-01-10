package com.cosium.openid_connect.mock.server;

import static java.util.Objects.requireNonNull;

import java.util.HashMap;
import java.util.Map;

/** @author Réda Housni Alaoui */
class Client {
  final String id;
  private final String secret;
  final Map<String, AuthorizationCode> authorizationCodesByValue = new HashMap<>();

  Client(String id, String secret) {
    this.id = requireNonNull(id);
    this.secret = requireNonNull(secret);
  }

  boolean matchSecret(String secret) {
    return this.secret.equals(secret);
  }
}
