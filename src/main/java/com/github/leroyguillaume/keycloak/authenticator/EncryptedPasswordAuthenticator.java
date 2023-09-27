package com.github.leroyguillaume.keycloak.authenticator;

import java.security.Key;

import javax.crypto.Cipher;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class EncryptedPasswordAuthenticator implements Authenticator {

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String password = retrievePassword(context);
    KeycloakSession session = context.getSession();

    KeyWrapper key = session.keys().getActiveKey(context.getRealm(), KeyUse.ENC, "RSA-OAEP");

    var encodedBytes = Base64Url.decode(password);
    byte[] decodedBytes;
    try {
      decodedBytes = decode(encodedBytes, key.getPrivateKey());
    } catch (Exception e) {
      e.printStackTrace();

      context.failure(
          AuthenticationFlowError.INTERNAL_ERROR,
          errorResponse(
              Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
              "internal_error",
              "Internal error"));
      return;
    }

    String decryptedPassword = new String(decodedBytes);
    boolean valid = context.getUser().credentialManager().isValid(UserCredentialModel.password(decryptedPassword));
    if (!valid) {
      context.getEvent().user(context.getUser());
      context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
      Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant",
          "Invalid user credentials");
      context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }

    context.success();
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

  }

  @Override
  public void close() {

  }

  @Override
  public void action(AuthenticationFlowContext context) {

  }

  private byte[] decode(byte[] encoded, Key privateKey) throws Exception {
    Cipher cipher = getCipherProvider();
    initCipher(cipher, Cipher.DECRYPT_MODE, privateKey);
    return cipher.doFinal(encoded);
  }

  private Cipher getCipherProvider() throws Exception {
    return Cipher.getInstance("RSA");
  }

  private void initCipher(Cipher cipher, int mode, Key key) throws Exception {
    cipher.init(mode, key);
  }

  private String retrievePassword(AuthenticationFlowContext context) {
    final var inputData = context.getHttpRequest().getDecodedFormParameters();
    return inputData.getFirst(CredentialRepresentation.PASSWORD);
  }

  private Response errorResponse(int status, String error, String errorDescription) {
    OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
    return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
  }
}
