# Stage 1: build
FROM maven:3.9-eclipse-temurin-21-alpine AS builder
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn package -DskipTests -q

# Stage 2: runtime
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN mkdir /reports
COPY --from=builder /build/target/port-scanner-1.0-shaded.jar port-scanner.jar
ENTRYPOINT ["java", "-jar", "/app/port-scanner.jar"]
