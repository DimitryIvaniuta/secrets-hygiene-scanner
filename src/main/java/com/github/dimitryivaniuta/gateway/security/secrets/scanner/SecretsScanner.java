package com.github.dimitryivaniuta.gateway.security.secrets.scanner;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.LocationType;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanFinding;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanReport;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanStatus;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.git.JGitRepositoryReader;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.policy.SecretsAllowlist;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.policy.SecretsAllowlistService;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.rules.SecretRule;
import java.nio.file.FileSystems;
import java.nio.file.PathMatcher;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Predicate;
import lombok.RequiredArgsConstructor;

/** Main scanning engine. */
@RequiredArgsConstructor
public class SecretsScanner {

  private final Clock clock;
  private final JGitRepositoryReader git;
  private final List<SecretRule> rules;
  private final SecretsAllowlistService allowlistService;

  public ScanReport scan(String baseRef, String headRef, List<String> excludeGlobs, String allowlistFile) {
    SecretsAllowlist allowlist = allowlistService.loadIfPresent(allowlistFile).orElse(null);

    List<ScanFinding> findings = new ArrayList<>();
    String currentFile = null;
    Predicate<String> excluded = buildExcludePredicate(excludeGlobs);

    for (String line : git.readUnifiedDiffLines(baseRef, headRef)) {
      if (line.startsWith("+++ b/")) {
        currentFile = line.substring("+++ b/".length()).trim();
        continue;
      }
      if (line.startsWith("+") && !line.startsWith("+++")) {
        String content = line.substring(1);
        if (currentFile != null && excluded.test(currentFile)) continue;

        for (SecretRule r : rules) {
          var found = r.evaluate(LocationType.DIFF_LINE, currentFile, null, null, content);
          if (found.isPresent()) {
            var f = found.get();
            if (!allowlistService.isSuppressed(allowlist, f.ruleId(), f.filePath())) findings.add(f);
          }
        }
      }
    }

    for (String msgLine : git.readCommitMessageLines(baseRef, headRef)) {
      for (SecretRule r : rules) {
        var found = r.evaluate(LocationType.COMMIT_MESSAGE, null, null, null, msgLine);
        if (found.isPresent()) {
          var f = found.get();
          if (!allowlistService.isSuppressed(allowlist, f.ruleId(), f.filePath())) findings.add(f);
        }
      }
    }

    ScanStatus status = findings.isEmpty() ? ScanStatus.PASS : ScanStatus.FAIL;

    return new ScanReport(
        UUID.randomUUID(),
        Instant.now(clock),
        baseRef,
        headRef,
        status,
        findings.size(),
        List.copyOf(findings)
    );
  }

  private static Predicate<String> buildExcludePredicate(List<String> excludeGlobs) {
    if (excludeGlobs == null || excludeGlobs.isEmpty()) return p -> false;
    List<PathMatcher> matchers = excludeGlobs.stream()
        .map(g -> FileSystems.getDefault().getPathMatcher("glob:" + g))
        .toList();

    return path -> {
      var p = java.nio.file.Path.of(path);
      for (PathMatcher m : matchers) if (m.matches(p)) return true;
      return false;
    };
  }
}
