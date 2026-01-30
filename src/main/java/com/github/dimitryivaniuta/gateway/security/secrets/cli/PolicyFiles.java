package com.github.dimitryivaniuta.gateway.security.secrets.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/** Loads `.secrets-policy.yml` from repo root. */
public final class PolicyFiles {

  private PolicyFiles() {}
  private static final Path POLICY_PATH = Path.of(".secrets-policy.yml");

  public static List<String> tryLoadPolicyExcludeGlobs() {
    if (!Files.exists(POLICY_PATH)) return Collections.emptyList();
    try {
      ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
      Policy p = mapper.readValue(Files.readString(POLICY_PATH), Policy.class);
      return p.excludeGlobs == null ? Collections.emptyList() : p.excludeGlobs;
    } catch (Exception e) {
      throw new IllegalStateException("Failed to read " + POLICY_PATH + ": " + e.getMessage(), e);
    }
  }

  public static Optional<String> tryLoadPolicyAllowlistFile() {
    if (!Files.exists(POLICY_PATH)) return Optional.empty();
    try {
      ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
      Policy p = mapper.readValue(Files.readString(POLICY_PATH), Policy.class);
      return Optional.ofNullable(p.allowlistFile);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to read " + POLICY_PATH + ": " + e.getMessage(), e);
    }
  }

  static final class Policy {
    public List<String> excludeGlobs;
    public String allowlistFile;
    public Boolean printRemediation;
  }
}
