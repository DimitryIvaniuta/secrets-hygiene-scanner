package com.github.dimitryivaniuta.gateway.security.secrets.web;

import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Thrown when a scan id is not found. */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class ScanNotFoundException extends RuntimeException {
  public ScanNotFoundException(UUID id) { super("Scan not found: " + id); }
}
