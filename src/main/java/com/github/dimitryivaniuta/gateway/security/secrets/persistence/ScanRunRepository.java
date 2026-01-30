package com.github.dimitryivaniuta.gateway.security.secrets.persistence;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Repository for scan runs. */
public interface ScanRunRepository extends JpaRepository<ScanRunEntity, UUID> {}
