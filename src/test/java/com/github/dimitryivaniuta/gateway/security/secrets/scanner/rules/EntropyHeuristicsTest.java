package com.github.dimitryivaniuta.gateway.security.secrets.scanner.rules;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/** Unit tests for entropy + redaction helpers. */
class EntropyHeuristicsTest {

  @Test
  void entropy_shouldBeHigherForRandomLookingStrings() {
    double low = EntropyHeuristics.shannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaa");
    double high = EntropyHeuristics.shannonEntropy("aZ8kP1mQv7W2xY9nR0tU3sL5");
    assertTrue(high > low);
  }

  @Test
  void redact_shouldHideMostCharacters() {
    String r = EntropyHeuristics.redactToken("ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    assertTrue(r.contains("…"));
    assertFalse(r.contains("abcdefghijklmnopqrstuvwxyz"));
  }
}
