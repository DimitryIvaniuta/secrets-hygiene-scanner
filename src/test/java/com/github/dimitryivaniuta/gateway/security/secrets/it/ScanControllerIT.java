package com.github.dimitryivaniuta.gateway.security.secrets.it;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.dimitryivaniuta.gateway.security.secrets.domain.LocationType;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanFinding;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanReport;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.ScanStatus;
import com.github.dimitryivaniuta.gateway.security.secrets.domain.Severity;
import com.github.dimitryivaniuta.gateway.security.secrets.persistence.ScanRunRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;
import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** End-to-end integration test with Postgres + Redis + Kafka using Testcontainers. */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ScanControllerIT {

  @Container
  static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16")
      .withDatabaseName("secrets_hygiene")
      .withUsername("app")
      .withPassword("app");

  @Container
  static final GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7")).withExposedPorts(6379);

  @Container
  static final KafkaContainer kafka = new KafkaContainer(DockerImageName.parse("confluentinc/cp-kafka:7.6.1"));

  @DynamicPropertySource
  static void props(DynamicPropertyRegistry r) {
    r.add("spring.datasource.url", postgres::getJdbcUrl);
    r.add("spring.datasource.username", postgres::getUsername);
    r.add("spring.datasource.password", postgres::getPassword);
    r.add("spring.data.redis.host", redis::getHost);
    r.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
    r.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
    r.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
  }

  @Autowired TestRestTemplate http;
  @Autowired ScanRunRepository repo;

  @Test
  void submitShouldPersistAndReturnId() {
    UUID id = UUID.randomUUID();
    ScanReport report = new ScanReport(
        id, Instant.now(), "base", "head", ScanStatus.FAIL, 1,
        List.of(new ScanFinding("GITHUB_PAT", Severity.CRITICAL, LocationType.DIFF_LINE, "a.txt", null, null, "token: ghp_Abcd…Wxyz", "Rotate"))
    );

    ResponseEntity<String> resp = http.postForEntity("/api/scans", report, String.class);
    assertThat(resp.getStatusCode().value()).isEqualTo(201);
    assertThat(repo.findById(id)).isPresent();
  }
}
