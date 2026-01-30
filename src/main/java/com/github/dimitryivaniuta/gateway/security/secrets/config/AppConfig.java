package com.github.dimitryivaniuta.gateway.security.secrets.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Infrastructure beans. */
@Configuration
public class AppConfig {

  /** @return UTC clock for testability. */
  @Bean
  public Clock clock() {
    return Clock.systemUTC();
  }
}
