package com.github.dimitryivaniuta.gateway.security.secrets.persistence;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.LocationType;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.Severity;
import jakarta.persistence.*;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** JPA entity for one finding (redacted). */
@Entity
@Table(name = "scan_finding")
@Getter @Setter @NoArgsConstructor
public class ScanFindingEntity {

  @Id
  private UUID id;

  @ManyToOne(optional = false, fetch = FetchType.LAZY)
  @JoinColumn(name = "scan_run_id", nullable = false)
  private ScanRunEntity scanRun;

  @Column(name = "rule_id", nullable = false, length = 100)
  private String ruleId;

  @Enumerated(EnumType.STRING)
  @Column(name = "severity", nullable = false, length = 32)
  private Severity severity;

  @Enumerated(EnumType.STRING)
  @Column(name = "location_type", nullable = false, length = 32)
  private LocationType locationType;

  @Column(name = "file_path")
  private String filePath;

  @Column(name = "commit_id", length = 60)
  private String commitId;

  @Column(name = "line_number")
  private Integer lineNumber;

  @Column(name = "redacted_snippet", nullable = false)
  private String redactedSnippet;

  @Column(name = "guidance", nullable = false)
  private String guidance;
}
