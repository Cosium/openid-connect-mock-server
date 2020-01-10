package com.cosium.openid_connect.mock.server;

import static java.util.Objects.requireNonNull;

import java.security.SecureRandom;
import java.time.ZonedDateTime;
import java.util.Base64;

/** @author Réda Housni Alaoui */
class AuthorizationCode {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  final ZonedDateTime authenticationTime = ZonedDateTime.now();

  final String value;
  final Client client;
  final String redirectUri;
  final String nonce;

  AuthorizationCode(Client client, String redirectUri, String nonce) {
    this.client = requireNonNull(client);
    this.redirectUri = requireNonNull(redirectUri);
    this.nonce = requireNonNull(nonce);
    this.value = generateRandomToken();
  }

  private static String generateRandomToken() {
    byte[] buffer = new byte[10];
    SECURE_RANDOM.nextBytes(buffer);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
  }
}
