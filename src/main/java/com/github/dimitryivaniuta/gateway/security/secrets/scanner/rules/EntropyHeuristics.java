package com.github.dimitryivaniuta.gateway.security.secrets.scanner.rules;

import java.util.Locale;

/** Shannon entropy helper + redaction helpers. */
public final class EntropyHeuristics {

  private EntropyHeuristics() {}

  /** Calculates Shannon entropy (bits per char) for ASCII input. */
  public static double shannonEntropy(String s) {
    if (s == null || s.isEmpty()) return 0.0;
    int[] counts = new int[256];
    int n = 0;
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c < 256) { counts[c]++; n++; }
      else return 0.0;
    }
    if (n == 0) return 0.0;

    double entropy = 0.0;
    for (int count : counts) {
      if (count == 0) continue;
      double p = (double) count / n;
      entropy += -p * (Math.log(p) / Math.log(2));
    }
    return entropy;
  }

  /** Small placeholder dictionary to reduce false positives. */
  public static boolean isPlaceholder(String token) {
    if (token == null) return true;
    String t = token.trim().toLowerCase(Locale.ROOT);
    return t.isEmpty()
        || t.equals("changeme") || t.equals("change-me")
        || t.equals("password") || t.equals("passwd")
        || t.equals("secret") || t.equals("token")
        || t.equals("apikey") || t.equals("api-key")
        || t.equals("example") || t.equals("dummy")
        || t.equals("test") || t.equals("12345678") || t.equals("qwerty123");
  }

  /** Redacts a token by keeping small prefix/suffix. */
  public static String redactToken(String raw) {
    if (raw == null) return "<null>";
    String s = raw.trim();
    if (s.length() <= 10) return "<redacted>";
    int keep = 4;
    return s.substring(0, keep) + "…" + s.substring(s.length() - keep);
  }
}
