package com.github.dimitryivaniuta.gateway.security.secrets;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Secrets Hygiene Scanner service.
 *
 * <p>CI enforcement is done via the Gradle task {@code secretsScan} (see build.gradle).
 * This service is optional and can be used to persist scan reports + emit alerts.</p>
 */
@SpringBootApplication
public class SecretsHygieneScannerApplication {

  public static void main(String[] args) {
    SpringApplication.run(SecretsHygieneScannerApplication.class, args);
  }
}
