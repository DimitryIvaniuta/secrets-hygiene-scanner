package com.github.dimitryivaniuta.gateway.security.secrets.scanner.rules;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.LocationType;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanFinding;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.Severity;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects suspicious assignments like: password=AbC...random...
 * Uses entropy + placeholder filtering to keep false positives low.
 */
public class HighEntropyAssignmentRule implements SecretRule {

  private static final Pattern ASSIGNMENT =
      Pattern.compile("(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"]?([^\s'\"]{8,})");

  private final double entropyThreshold;
  private final int minLength;

  public HighEntropyAssignmentRule(double entropyThreshold, int minLength) {
    this.entropyThreshold = entropyThreshold;
    this.minLength = minLength;
  }

  @Override public String id() { return "GENERIC_ASSIGNMENT_HIGH_ENTROPY"; }

  @Override
  public Optional<ScanFinding> evaluate(LocationType locationType, String filePath, String commitId, Integer lineNumber, String line) {
    if (line == null) return Optional.empty();
    Matcher m = ASSIGNMENT.matcher(line);
    if (!m.find()) return Optional.empty();

    String value = m.group(2);
    if (value == null || value.length() < minLength) return Optional.empty();
    if (EntropyHeuristics.isPlaceholder(value)) return Optional.empty();

    double entropy = EntropyHeuristics.shannonEntropy(value);
    if (entropy < entropyThreshold) return Optional.empty();

    String redacted = line.replace(value, EntropyHeuristics.redactToken(value));
    String guidance = "Remove the secret from commit history (rotate/revoke), store it in a secret manager, "
        + "and reference it via env vars / workload identity at runtime.";

    return Optional.of(new ScanFinding(id(), Severity.HIGH, locationType, filePath, commitId, lineNumber, redacted, guidance));
  }
}
