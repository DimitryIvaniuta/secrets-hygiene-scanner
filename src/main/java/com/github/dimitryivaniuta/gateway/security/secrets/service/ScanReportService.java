package com.github.dimitryivaniuta.gateway.security.secrets.service;

import static com.github.dimitryivaniuta.gateway.security.secrets.config.KafkaTopicsConfig.TOPIC_SECURITY_SECRETS_ALERTS;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanFinding;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanReport;
import com.github.dimitryivaniuta.gateway.security.secrets.persistence.ScanFindingEntity;
import com.github.dimitryivaniuta.gateway.security.secrets.persistence.ScanRunEntity;
import com.github.dimitryivaniuta.gateway.security.secrets.persistence.ScanRunRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists scan reports and emits alerts.
 *
 * Only redacted snippets are stored.
 */
@Service
@RequiredArgsConstructor
public class ScanReportService {

  private final ScanRunRepository repo;
  private final KafkaTemplate<String, Object> kafkaTemplate;
  private final StringRedisTemplate redis;

  /** Stores the report and publishes Kafka alert if failed. */
  @Transactional
  public UUID storeAndAlert(ScanReport report) {
    ScanRunEntity run = new ScanRunEntity();
    run.setId(report.scanId());
    run.setCreatedAt(report.createdAt());
    run.setBaseRef(report.baseRef());
    run.setHeadRef(report.headRef());
    run.setStatus(report.status());
    run.setFindingsCount(report.findingsCount());

    for (ScanFinding f : report.findings()) {
      ScanFindingEntity e = new ScanFindingEntity();
      e.setId(UUID.randomUUID());
      e.setScanRun(run);
      e.setRuleId(f.ruleId());
      e.setSeverity(f.severity());
      e.setLocationType(f.locationType());
      e.setFilePath(f.filePath());
      e.setCommitId(f.commitId());
      e.setLineNumber(f.lineNumber());
      e.setRedactedSnippet(f.redactedSnippet());
      e.setGuidance(f.guidance());
      run.getFindings().add(e);
    }

    repo.save(run);

    redis.opsForValue().set("secrets:lastScanId", run.getId().toString());
    redis.opsForValue().set("secrets:lastScanStatus", run.getStatus().name());

    if (report.findingsCount() > 0) {
      kafkaTemplate.send(TOPIC_SECURITY_SECRETS_ALERTS, run.getId().toString(),
          new AlertEvent(run.getId().toString(), run.getCreatedAt().toString(), run.getBaseRef(), run.getHeadRef(), run.getFindingsCount()));
    }

    return run.getId();
  }

  /** Kafka alert payload. */
  public record AlertEvent(String scanId, String createdAt, String baseRef, String headRef, int findingsCount) {}
}
