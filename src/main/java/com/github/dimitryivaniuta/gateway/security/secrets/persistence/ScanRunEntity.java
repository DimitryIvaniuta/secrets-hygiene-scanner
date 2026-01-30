package com.github.dimitryivaniuta.gateway.security.secrets.persistence;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanStatus;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** JPA entity for a scan run. */
@Entity
@Table(name = "scan_run")
@Getter @Setter @NoArgsConstructor
public class ScanRunEntity {

  @Id
  private UUID id;

  @Column(name = "created_at", nullable = false)
  private Instant createdAt;

  @Column(name = "base_ref", nullable = false, length = 200)
  private String baseRef;

  @Column(name = "head_ref", nullable = false, length = 200)
  private String headRef;

  @Enumerated(EnumType.STRING)
  @Column(name = "status", nullable = false, length = 32)
  private ScanStatus status;

  @Column(name = "findings_count", nullable = false)
  private int findingsCount;

  @OneToMany(mappedBy = "scanRun", cascade = CascadeType.ALL, orphanRemoval = true)
  private List<ScanFindingEntity> findings = new ArrayList<>();
}
