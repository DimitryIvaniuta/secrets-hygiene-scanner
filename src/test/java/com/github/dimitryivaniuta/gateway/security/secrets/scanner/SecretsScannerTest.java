package com.github.dimitryivaniuta.gateway.security.secrets.scanner;

import static org.junit.jupiter.api.Assertions.*;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanStatus;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.git.JGitRepositoryReader;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.policy.SecretsAllowlistService;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.rules.DefaultRulesCatalog;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/** Unit test for scanner engine (mocking git reader). */
class SecretsScannerTest {

  @Test
  void shouldDetectGithubPatInDiffAdditions() {
    JGitRepositoryReader git = Mockito.mock(JGitRepositoryReader.class);
    Mockito.when(git.readUnifiedDiffLines("base", "head")).thenReturn(List.of(
        "diff --git a/a.txt b/a.txt",
        "+++ b/a.txt",
        "+token=ghp_abcdefghijklmnopqrstuvwxyzABCDE1234567890"
    ));
    Mockito.when(git.readCommitMessageLines("base", "head")).thenReturn(List.of());

    SecretsScanner scanner = new SecretsScanner(
        Clock.systemUTC(),
        git,
        DefaultRulesCatalog.rules(),
        new SecretsAllowlistService(Clock.systemUTC())
    );

    var report = scanner.scan("base", "head", List.of(), "non-existent.yml");
    assertEquals(ScanStatus.FAIL, report.status());
    assertTrue(report.findingsCount() >= 1);
    assertTrue(report.findings().stream().anyMatch(f -> f.ruleId().equals("GITHUB_PAT")));
  }

  @Test
  void shouldIgnoreExcludedFiles() {
    JGitRepositoryReader git = Mockito.mock(JGitRepositoryReader.class);
    Mockito.when(git.readUnifiedDiffLines("base", "head")).thenReturn(List.of(
        "+++ b/build/generated.txt",
        "+token=ghp_abcdefghijklmnopqrstuvwxyzABCDE1234567890"
    ));
    Mockito.when(git.readCommitMessageLines("base", "head")).thenReturn(List.of());

    SecretsScanner scanner = new SecretsScanner(
        Clock.systemUTC(), git, DefaultRulesCatalog.rules(), new SecretsAllowlistService(Clock.systemUTC())
    );

    var report = scanner.scan("base", "head", List.of("**/build/**"), "non-existent.yml");
    assertEquals(ScanStatus.PASS, report.status());
    assertEquals(0, report.findingsCount());
  }
}
