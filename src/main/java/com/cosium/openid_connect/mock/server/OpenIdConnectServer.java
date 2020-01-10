package com.cosium.openid_connect.mock.server;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;

/**
 * @author Réda Housni Alaoui
 */
public class OpenIdConnectServer {

	private static final String ADDRESS_TEMPLATE = "http://127.0.0.1:%s";

	private static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();
	private static final String KEY_ALIAS = "oidcserver";
	private static final char[] KEY_PASSWORD = "changeit".toCharArray();

	private static final String KTY = "RSA";
	private static final String ALGORITHM = "RS256";

	private static final String SUB = UUID.randomUUID().toString();
	private static final String BEARER_TYPE = "Bearer";
	private static final String REFRESH_TYPE = "Offline";
	private static final String ID_TYPE = "ID";

	private final RSAPrivateKey rsaPrivateKey;
	private final RSAPublicKey rsaPublicKey;

	private final Vertx vertx;
	private final HttpServer server;
	private final URI uri;

	private final Map<String, Client> clientById = new HashMap<>();

	private OpenIdConnectServer()
			throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
			UnrecoverableKeyException {
		String keystoreName = "keystore.pkcs12";
		KeyStore keyStore = KeyStore.getInstance("pkcs12");
		try (InputStream keystoreStream = getClass().getResourceAsStream(keystoreName)) {
			keyStore.load(keystoreStream, KEYSTORE_PASSWORD);
		}

		if (!keyStore.containsAlias(KEY_ALIAS)) {
			throw new IllegalStateException(
					"Could not find alias " + KEY_ALIAS + " in keystore " + keystoreName);
		}
		Key key = keyStore.getKey(KEY_ALIAS, KEY_PASSWORD);
		if (!(key instanceof RSAPrivateKey)) {
			throw new IllegalStateException(
					"Alias "
							+ KEY_ALIAS
							+ " of keystore "
							+ keystoreName
							+ " is not bound to an RSA private key");
		}
		rsaPrivateKey = (RSAPrivateKey) key;

		Certificate certificate = keyStore.getCertificate(KEY_ALIAS);
		PublicKey publicKey = certificate.getPublicKey();
		if (!(publicKey instanceof RSAPublicKey)) {
			throw new IllegalStateException(
					"Alias "
							+ KEY_ALIAS
							+ " of keystore "
							+ keystoreName
							+ " is not bound to an RSA public key");
		}
		rsaPublicKey = (RSAPublicKey) publicKey;

		vertx = Vertx.vertx();
		Router router = Router.router(vertx);
		router.route().handler(BodyHandler.create());

		server = vertx.createHttpServer().requestHandler(router);

		CountDownLatch serverStartedLatch = new CountDownLatch(1);
		server.listen(0, event -> serverStartedLatch.countDown());
		try {
			serverStartedLatch.await();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new RuntimeException(e);
		}
		uri = URI.create(String.format(ADDRESS_TEMPLATE, server.actualPort()));

		router.get("/auth").handler(this::authenticate);
		router.post("/token").handler(this::createToken);
		router.get("/certs").handler(this::getJWKSet);
	}

	public URI uri() {
		return uri;
	}

	public static OpenIdConnectServer start() {
		try {
			return new OpenIdConnectServer();
		} catch (KeyStoreException
				| IOException
				| CertificateException
				| NoSuchAlgorithmException
				| UnrecoverableKeyException e) {
			throw new RuntimeException(e);
		}
	}

	public void registerClient(String id, String secret) {
		clientById.put(id, new Client(id, secret));
	}

	public void stop() {
		server.close();
	}

	public void reset() {
		clientById.clear();
	}

	private void authenticate(RoutingContext routingContext) {
		HttpServerRequest request = routingContext.request();

		String clientId = request.getParam("client_id");
		Client client = clientById.get(clientId);
		if (client == null) {
			routingContext.response().setStatusCode(404).end();
			return;
		}

		String state = request.getParam("state");
		String redirectUri = request.getParam("redirect_uri");
		String nonce = request.getParam("nonce");

		AuthorizationCode authorizationCode = new AuthorizationCode(client, redirectUri, nonce);
		client.authorizationCodesByValue.put(authorizationCode.value, authorizationCode);

		routingContext
				.response()
				.setStatusCode(302)
				.putHeader("Location", redirectUri + "?code=" + authorizationCode.value + "&state=" + state)
				.end();
	}

	private void createToken(RoutingContext routingContext) {
		ClientAuthentication clientAuthentication = new ClientAuthentication(routingContext.request());
		if (!clientAuthentication.isComplete()) {
			routingContext.response().setStatusCode(401).end();
			return;
		}

		Client client = clientById.get(clientAuthentication.clientId);
		if (client == null) {
			routingContext.response().setStatusCode(401).end();
			return;
		}

		if (!client.matchSecret(clientAuthentication.clientSecret)) {
			routingContext.response().setStatusCode(401).end();
			return;
		}

		HttpServerRequest request = routingContext.request();

		String grantType = request.getFormAttribute("grant_type");
		if (!"authorization_code".equals(grantType)) {
			routingContext.response().setStatusCode(400).end();
			return;
		}

		String authorizationCodeValue = routingContext.request().getFormAttribute("code");
		AuthorizationCode authorizationCode =
				client.authorizationCodesByValue.get(authorizationCodeValue);
		if (authorizationCode == null) {
			routingContext.response().setStatusCode(401).end();
			return;
		}

		String redirectUri = request.getFormAttribute("redirect_uri");
		if (!authorizationCode.redirectUri.equals(redirectUri)) {
			routingContext.response().setStatusCode(401).end();
			return;
		}

		PubSecKeyOptions pubSecKeyOptions =
				new PubSecKeyOptions()
						.setAlgorithm(ALGORITHM)
						.setPublicKey(Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded()))
						.setSecretKey(Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded()));

		JWTAuthOptions jwtAuthOptions = new JWTAuthOptions().addPubSecKey(pubSecKeyOptions);

		JWTAuth jwtProvider = JWTAuth.create(vertx, jwtAuthOptions);
		JWTOptions jwtOptions = new JWTOptions().setAlgorithm(ALGORITHM);

		String accessToken =
				jwtProvider.generateToken(createJwtClaims(authorizationCode, BEARER_TYPE), jwtOptions);
		String refreshToken =
				jwtProvider.generateToken(createJwtClaims(authorizationCode, REFRESH_TYPE), jwtOptions);
		String idToken =
				jwtProvider.generateToken(createJwtClaims(authorizationCode, ID_TYPE), jwtOptions);

		JsonObject fullToken =
				new JsonObject()
						.put("access_token", accessToken)
						.put("expires_in", 60)
						.put("refresh_expires_in", 0)
						.put("refresh_token", refreshToken)
						.put("token_type", "bearer")
						.put("id_token", idToken)
						.put("not-before-policy", 0)
						.put("scope", "openid");

		routingContext
				.response()
				.putHeader("content-type", "application/json")
				.end(fullToken.encodePrettily());
	}

	private void getJWKSet(RoutingContext routingContext) {
		JsonObject jwk =
				new JsonObject()
						.put("kty", KTY)
						.put("alg", ALGORITHM)
						.put("use", "sig")
						.put(
								"e",
								Base64.getEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray()))
						.put("n", Base64.getEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray()));

		routingContext
				.response()
				.end(new JsonObject().put("keys", new JsonArray().add(jwk)).encodePrettily());
	}

	private JsonObject createJwtClaims(AuthorizationCode authorizationCode, String type) {
		long exp = ZonedDateTime.now().plus(1, ChronoUnit.DAYS).toEpochSecond();
		long iat = ZonedDateTime.now().toEpochSecond();

		JsonObject claims =
				new JsonObject()
						.put("jti", UUID.randomUUID().toString())
						.put("exp", exp)
						.put("nbf", 0)
						.put("iat", iat)
						.put("iss", uri.toString())
						.put("sub", SUB)
						.put("typ", type)
						.put("azp", authorizationCode.client.id)
						.put("nonce", authorizationCode.nonce);

		if (BEARER_TYPE.equals(type) || ID_TYPE.equals(type)) {
			claims.put("auth_time", authorizationCode.authenticationTime.toEpochSecond());
		} else {
			claims.put("auth_time", 0);
		}

		if (BEARER_TYPE.equals(type) || ID_TYPE.equals(type)) {
			claims.put("acr", 0);
		}

		if (BEARER_TYPE.equals(type) || REFRESH_TYPE.equals(type)) {
			claims.put("scope", "openid");
		}

		if (REFRESH_TYPE.equals(type)) {
			claims.put("aud", uri.toString());
		} else if (ID_TYPE.equals(type)) {
			claims.put("aud", authorizationCode.client.id);
		}

		return claims;
	}
}
