package com.github.leroyguillaume.keycloak.bcrypt.sha512;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCryptPasswordHashProvider implements PasswordHashProvider {
    private final int defaultIterations;
    private final String providerId;

    public BCryptPasswordHashProvider(final String providerId, final int defaultIterations) {
        this.providerId = providerId;
        this.defaultIterations = defaultIterations;
    }

    @Override
    public boolean policyCheck(final PasswordPolicy policy, final PasswordCredentialModel credential) {
        final int policyHashIterations = policy.getHashIterations() == -1 ? defaultIterations
                : policy.getHashIterations();

        return credential.getPasswordCredentialData().getHashIterations() == policyHashIterations
                && providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
    }

    @Override
    public PasswordCredentialModel encodedCredential(final String rawPassword, final int iterations) {
        final String encodedPassword = encode(rawPassword, iterations);

        // bcrypt salt is stored as part of the encoded password so no need to store
        // salt separately
        return PasswordCredentialModel.createFromValues(providerId, new byte[0], iterations, encodedPassword);
    }

    @Override
    public String encode(final String rawPassword, final int iterations) {
        String hashedRawPassword = rawPassword;
        try {
            hashedRawPassword = hashPassword(rawPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        final int cost = iterations == -1 ? defaultIterations : iterations;
        return new BCryptPasswordEncoder(cost).encode(hashedRawPassword);
    }

    @Override
    public void close() {

    }

    @Override
    public boolean verify(final String rawPassword, final PasswordCredentialModel credential) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String hashedRawPassword = rawPassword;
        try {
            hashedRawPassword = hashPassword(rawPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        final String hash = credential.getPasswordSecretData().getValue();

        return encoder.matches(hashedRawPassword, hash);
    }

    private String hashPassword(String password) throws NoSuchAlgorithmException {
        String hashPass = null;

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] bytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        hashPass = sb.toString();

        return hashPass;
    }
}
