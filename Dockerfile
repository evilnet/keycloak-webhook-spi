# Multi-stage build for Keycloak with webhook SPI

# Stage 1: Build the SPI with Maven
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /build

# Copy pom.xml first for dependency caching
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build
COPY src/ src/
RUN mvn clean package -DskipTests -B

# Stage 2: Keycloak with the SPI installed
FROM quay.io/keycloak/keycloak:26.0.0

# Copy the built SPI JAR
COPY --from=builder /build/target/keycloak-webhook-spi-*.jar /opt/keycloak/providers/

# Build Keycloak to register the provider
RUN /opt/keycloak/bin/kc.sh build

# Default entrypoint and command from base image
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
