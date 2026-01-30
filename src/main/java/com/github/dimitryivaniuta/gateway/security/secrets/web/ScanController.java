package com.github.dimitryivaniuta.gateway.security.secrets.web;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanReport;
import com.github.dimitryivaniuta.gateway.security.secrets.persistence.ScanRunRepository;
import com.github.dimitryivaniuta.gateway.security.secrets.service.ScanReportService;
import jakarta.validation.Valid;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

/** REST API for receiving and querying scan reports. */
@RestController
@RequestMapping("/api/scans")
@RequiredArgsConstructor
public class ScanController {

  private final ScanReportService service;
  private final ScanRunRepository repo;

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public ScanCreatedResponse submit(@Valid @RequestBody ScanReport report) {
    UUID id = service.storeAndAlert(report);
    return new ScanCreatedResponse(id.toString());
  }

  @GetMapping("/{id}")
  public ScanRunView get(@PathVariable UUID id) {
    var run = repo.findById(id).orElseThrow(() -> new ScanNotFoundException(id));
    return new ScanRunView(run.getId().toString(), run.getCreatedAt().toString(), run.getBaseRef(), run.getHeadRef(), run.getStatus().name(), run.getFindingsCount());
  }

  public record ScanCreatedResponse(String id) {}
  public record ScanRunView(String id, String createdAt, String baseRef, String headRef, String status, int findingsCount) {}
}
