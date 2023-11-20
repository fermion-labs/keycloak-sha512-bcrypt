package com.github.leroyguillaume.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class LogoutSessionAuthenticator implements Authenticator {
  protected static final Logger logger = Logger.getLogger(LogoutSessionAuthenticator.class);

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    var authSession = context.getAuthenticationSession();
    var session = context.getSession();

    var userSession = session.sessions().getUserSession(context.getRealm(), authSession.getParentSession().getId());

    if (userSession != null) {
      session.sessions().removeUserSession(context.getRealm(), userSession);
    }
    context.success();
  }

  @Override
  public void close() {

  }

  @Override
  public void action(AuthenticationFlowContext context) {

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
}
