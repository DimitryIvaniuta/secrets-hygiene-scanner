package com.github.dimitryivaniuta.gateway.security.secrets.scanner.rules;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.Severity;
import java.util.List;
import java.util.regex.Pattern;

/** Built-in catalog of detection rules (balanced for low false positives). */
public final class DefaultRulesCatalog {

  private DefaultRulesCatalog() {}

  public static List<SecretRule> rules() {
    return List.of(
        new RegexSecretRule("AWS_ACCESS_KEY_ID", Severity.CRITICAL,
            Pattern.compile("\bAKIA[0-9A-Z]{16}\b"), 0,
            "Revoke the key immediately, rotate credentials, and remove from git history."),
        new RegexSecretRule("GITHUB_PAT", Severity.CRITICAL,
            Pattern.compile("\bghp_[A-Za-z0-9]{36}\b"), 0,
            "Revoke the token, rotate, and remove from git history."),
        new RegexSecretRule("PRIVATE_KEY_BLOCK", Severity.CRITICAL,
            Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0,
            "Never commit private keys. Remove, rotate keys, and use secure storage."),
        new RegexSecretRule("SLACK_TOKEN", Severity.HIGH,
            Pattern.compile("\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0,
            "Rotate the Slack token and remove it from git history."),
        new RegexSecretRule("JWT_TOKEN", Severity.MEDIUM,
            Pattern.compile("\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), 0,
            "If this is a real JWT, rotate/revoke it. Avoid pasting JWTs into code/commits/logs."),
        new HighEntropyAssignmentRule(4.1, 20)
    );
  }
}
