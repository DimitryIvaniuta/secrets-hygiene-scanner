package com.github.dimitryivaniuta.gateway.security.secrets.scanner.rules;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.LocationType;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanFinding;
import java.util.Optional;

/** One detection rule. */
public interface SecretRule {

  /** Rule id used in reporting and allowlist. */
  String id();

  /** Evaluates a line and returns a finding if matched. */
  Optional<ScanFinding> evaluate(LocationType locationType, String filePath, String commitId, Integer lineNumber, String line);
}
