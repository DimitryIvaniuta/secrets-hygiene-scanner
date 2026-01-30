package com.github.dimitryivaniuta.gateway.security.secrets.domain;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Immutable scan report produced by the scanner.
 *
 * <p>Design note: the scanner returns redacted snippets and never stores raw secrets.</p>
 */
public record ScanReport(
    @NotNull UUID scanId,
    @NotNull Instant createdAt,
    @NotBlank String baseRef,
    @NotBlank String headRef,
    @NotNull ScanStatus status,
    int findingsCount,
    @NotNull List<ScanFinding> findings
) {}
