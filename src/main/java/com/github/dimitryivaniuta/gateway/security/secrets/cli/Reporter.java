package com.github.dimitryivaniuta.gateway.security.secrets.cli;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanFinding;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanReport;

/** Human-readable output for CI logs (redacted only). */
public final class Reporter {

  private Reporter() {}

  public static void printHumanReadable(ScanReport report, String jsonOutputPath) {
    System.out.println("=== Secrets Hygiene Scan ===");
    System.out.println("Range: " + report.baseRef() + ".." + report.headRef());
    System.out.println("Status: " + report.status());
    System.out.println("Findings: " + report.findingsCount());
    System.out.println("JSON report: " + jsonOutputPath);
    System.out.println();

    for (ScanFinding f : report.findings()) {
      System.out.println("- [" + f.severity() + "] " + f.ruleId());
      if (f.filePath() != null) System.out.println("  file: " + f.filePath());
      System.out.println("  location: " + f.locationType());
      System.out.println("  snippet: " + f.redactedSnippet());
      System.out.println("  guidance: " + f.guidance());
      System.out.println();
    }

    if (report.findingsCount() > 0) {
      System.out.println("Remediation checklist:");
      System.out.println("1) Revoke/rotate the leaked credential immediately.");
      System.out.println("2) Remove it from Git history (git filter-repo/BFG) and force-push if needed.");
      System.out.println("3) Store secrets in a secret manager (GitHub/Azure/AWS secrets, Vault, Key Vault, SSM).");
      System.out.println("4) Replace with references (env vars / workload identity / short-lived tokens).");
      System.out.println("5) Re-run pipeline until report is clean.");
      System.out.println();
      System.out.println("False positive? Add a narrow suppression to .secrets-allowlist.yml with reason + expiry.");
    }
  }
}
