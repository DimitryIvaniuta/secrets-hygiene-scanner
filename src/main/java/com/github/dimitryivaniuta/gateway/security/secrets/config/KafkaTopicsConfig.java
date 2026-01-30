package com.github.dimitryivaniuta.gateway.security.secrets.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

/** Kafka topics for security alerts. */
@Configuration
public class KafkaTopicsConfig {

  /** Topic name for secret scan alerts. */
  public static final String TOPIC_SECURITY_SECRETS_ALERTS = "security.secrets.alerts";

  /** Creates topic in local/dev (prod should use IaC). */
  @Bean
  public NewTopic securitySecretsAlertsTopic() {
    return TopicBuilder.name(TOPIC_SECURITY_SECRETS_ALERTS).partitions(1).replicas(1).build();
  }
}
