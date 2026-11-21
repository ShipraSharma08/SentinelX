# Stage 1: Build the Spring Boot application
FROM maven:3.9.9-eclipse-temurin-21 AS build

WORKDIR /app

COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn

RUN chmod +x mvnw

COPY src ./src

RUN ./mvnw -B -DskipTests package


# Stage 2: Run the application securely
FROM eclipse-temurin:21-jre

WORKDIR /app

# Create a dedicated non-root user
RUN groupadd --system spring \
    && useradd --system --gid spring --create-home spring

# Copy application JAR with correct ownership
COPY --from=build --chown=spring:spring /app/target/*.jar app.jar

# Run as non-root user
USER spring:spring

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
