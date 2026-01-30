package com.github.dimitryivaniuta.gateway.security.secrets.scanner.policy;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import lombok.Data;

/**
 * YAML allowlist for suppressions.
 *
 * <p>Suppressions MUST expire.</p>
 */
@Data
public class SecretsAllowlist {

  private List<Suppression> suppressions = new ArrayList<>();

  @Data
  public static class Suppression {
    private String ruleId;
    private String pathRegex;
    private String reason;
    private LocalDate expiresOn;
  }
}
