package com.github.dimitryivaniuta.gateway.security.secrets.scanner.rules;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.LocationType;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanFinding;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.Severity;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;

/** Regex rule that redacts a matched group. */
@RequiredArgsConstructor
public class RegexSecretRule implements SecretRule {

  private final String id;
  private final Severity severity;
  private final Pattern pattern;
  private final int sensitiveGroup;
  private final String guidance;

  @Override public String id() { return id; }

  @Override
  public Optional<ScanFinding> evaluate(LocationType locationType, String filePath, String commitId, Integer lineNumber, String line) {
    if (line == null) return Optional.empty();
    Matcher m = pattern.matcher(line);
    if (!m.find()) return Optional.empty();

    String raw = (sensitiveGroup > 0 && m.groupCount() >= sensitiveGroup) ? m.group(sensitiveGroup) : m.group();
    String redacted = line.replace(raw, EntropyHeuristics.redactToken(raw));

    return Optional.of(new ScanFinding(id, severity, locationType, filePath, commitId, lineNumber, redacted, guidance));
  }
}
