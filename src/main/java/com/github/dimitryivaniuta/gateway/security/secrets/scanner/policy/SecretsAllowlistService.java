package com.github.dimitryivaniuta.gateway.security.secrets.scanner.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;

/** Loads and evaluates suppressions (allowlist). */
@RequiredArgsConstructor
public class SecretsAllowlistService {

  private final Clock clock;

  /** Loads allowlist from file if present. */
  public Optional<SecretsAllowlist> loadIfPresent(String allowlistFile) {
    if (allowlistFile == null || allowlistFile.isBlank()) return Optional.empty();
    Path path = Path.of(allowlistFile);
    if (!Files.exists(path)) return Optional.empty();

    ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
    try (var in = Files.newInputStream(path)) {
      return Optional.of(mapper.readValue(in, SecretsAllowlist.class));
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read allowlist file: " + allowlistFile, e);
    }
  }

  /** Returns true if a finding is suppressed by allowlist and not expired. */
  public boolean isSuppressed(SecretsAllowlist allowlist, String ruleId, String filePath) {
    if (allowlist == null) return false;
    if (filePath == null) filePath = "";

    LocalDate today = LocalDate.now(clock);
    List<SecretsAllowlist.Suppression> sups = allowlist.getSuppressions();
    if (sups == null) return false;

    for (var s : sups) {
      if (s.getRuleId() == null || s.getPathRegex() == null || s.getExpiresOn() == null) continue;
      if (!s.getRuleId().equals(ruleId)) continue;
      if (s.getExpiresOn().isBefore(today)) continue;

      Pattern p = Pattern.compile(s.getPathRegex());
      if (p.matcher(filePath).find()) return true;
    }
    return false;
  }
}
