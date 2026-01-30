package com.github.dimitryivaniuta.gateway.security.secrets.domain;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * One secret-like finding.
 *
 * <p>Only redacted snippets are stored/printed.</p>
 */
public record ScanFinding(
    @NotBlank String ruleId,
    @NotNull Severity severity,
    @NotNull LocationType locationType,
    String filePath,
    String commitId,
    Integer lineNumber,
    @NotBlank String redactedSnippet,
    @NotBlank String guidance
) {}
