package com.github.leroyguillaume.keycloak.authenticator;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class EncryptedPasswordAuthenticatorFactory
    implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "encrypted-password-authenticator";

  private static final EncryptedPasswordAuthenticator SINGLETON = new EncryptedPasswordAuthenticator();

  @Override
  public String getDisplayType() {
    return "Encrypted Password Authenticator";
  }

  @Override
  public String getReferenceCategory() {
    return "password";
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return EncryptedPasswordAuthenticatorFactory.REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Encrypted Password Authenticator";
  }

  private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.ALTERNATIVE,
      AuthenticationExecutionModel.Requirement.DISABLED
  };

  @Override
  public Authenticator create(KeycloakSession keycloakSession) {
    return SINGLETON;
  }

  @Override
  public String getId() {
    return EncryptedPasswordAuthenticatorFactory.PROVIDER_ID;
  }

  @Override
  public void init(Scope config) {

  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {

  }

  @Override
  public void close() {

  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return new ArrayList<ProviderConfigProperty>();
  }

}
