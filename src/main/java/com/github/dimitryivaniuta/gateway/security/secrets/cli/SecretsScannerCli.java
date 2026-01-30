package com.github.dimitryivaniuta.gateway.security.secrets.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanReport;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.SecretsScanner;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.git.JGitRepositoryReader;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.policy.SecretsAllowlistService;
import com.github.dimitryivaniuta.gateway.security.secrets.scanner.rules.DefaultRulesCatalog;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;

/**
 * CLI used by CI to enforce the "no secrets in commits" policy.
 *
 * Exit codes:
 *  - 0: no findings
 *  - 2: findings (policy violation)
 *  - 3: usage error
 */
public final class SecretsScannerCli {

  private SecretsScannerCli() {}

  public static void main(String[] args) throws Exception {
    Args a = Args.parse(args);
    if (!a.valid) {
      System.err.println(Args.usage());
      System.exit(3);
      return;
    }

    Clock clock = Clock.systemUTC();
    SecretsScanner scanner = new SecretsScanner(
        clock,
        new JGitRepositoryReader(Path.of(".")),
        DefaultRulesCatalog.rules(),
        new SecretsAllowlistService(clock)
    );

    List<String> exclude = PolicyFiles.tryLoadPolicyExcludeGlobs();
    String allowlistFile = PolicyFiles.tryLoadPolicyAllowlistFile().orElse(".secrets-allowlist.yml");

    ScanReport report = scanner.scan(a.base, a.head, exclude, allowlistFile);

    ObjectMapper om = new ObjectMapper();
    String json = om.writerWithDefaultPrettyPrinter().writeValueAsString(report);

    Path out = Path.of(a.output);
    Files.createDirectories(out.getParent());
    Files.writeString(out, json);

    if ("json".equalsIgnoreCase(a.format)) System.out.println(json);
    else Reporter.printHumanReadable(report, a.output);

    if (a.postUrl != null && !a.postUrl.isBlank()) postReport(a.postUrl, json);

    System.exit(report.findingsCount() == 0 ? 0 : 2);
  }

  private static void postReport(String url, String json) {
    try {
      HttpClient client = HttpClient.newHttpClient();
      HttpRequest req = HttpRequest.newBuilder()
          .uri(URI.create(url))
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(json))
          .build();

      HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
      if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
        System.err.println("Warning: failed to POST report to " + url + " status=" + resp.statusCode());
      }
    } catch (Exception e) {
      System.err.println("Warning: failed to POST report to " + url + " error=" + e.getMessage());
    }
  }

  static final class Args {
    final boolean valid;
    final String base, head, format, output, postUrl;

    private Args(boolean valid, String base, String head, String format, String output, String postUrl) {
      this.valid = valid; this.base = base; this.head = head; this.format = format; this.output = output; this.postUrl = postUrl;
    }

    static Args parse(String[] args) {
      String base = null, head = null, format = "text", output = "build/reports/secrets-scan/report.json", postUrl = null;
      for (int i = 0; i < args.length; i++) {
        String k = args[i];
        if ("--base".equals(k) && i + 1 < args.length) base = args[++i];
        else if ("--head".equals(k) && i + 1 < args.length) head = args[++i];
        else if ("--format".equals(k) && i + 1 < args.length) format = args[++i];
        else if ("--output".equals(k) && i + 1 < args.length) output = args[++i];
        else if ("--post-url".equals(k) && i + 1 < args.length) postUrl = args[++i];
        else if ("--help".equals(k) || "-h".equals(k)) return new Args(false, null, null, null, null, null);
      }
      if (base == null || head == null) return new Args(false, base, head, format, output, postUrl);
      return new Args(true, base, head, format, output, postUrl);
    }

    static String usage() {
      return "Usage: secrets-scan --base <ref> --head <ref> [--format text|json] [--output <path>] [--post-url <url>]\n"
          + "Example: ./gradlew -Pbase=origin/main -Phead=HEAD secretsScan\n";
    }
  }
}
