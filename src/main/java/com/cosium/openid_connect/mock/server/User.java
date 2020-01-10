package com.cosium.openid_connect.mock.server;

import static java.util.Objects.requireNonNull;

/** @author Réda Housni Alaoui */
public class User {

  final String subject;
  final String name;
  final String givenName;
  final String familyName;

  private User(Builder builder) {
    this.subject = requireNonNull(builder.subject);
    this.name = builder.name;
    this.givenName = builder.givenName;
    this.familyName = builder.familyName;
  }

  public static class Builder {

    private String subject;
    private String name;
    private String givenName;
    private String familyName;

    private Builder() {}

    public Builder subject(String subject) {
      this.subject = subject;
      return this;
    }

    public Builder name(String name) {
      this.name = name;
      return this;
    }

    public Builder givenName(String givenName) {
      this.givenName = givenName;
      return this;
    }

    public Builder familyName(String familyName) {
      this.familyName = familyName;
      return this;
    }

    public User build() {
      return new User(this);
    }
  }
}
