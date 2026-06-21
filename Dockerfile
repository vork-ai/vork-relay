FROM maven:3.9.11-eclipse-temurin-21 AS build

WORKDIR /workspace

# Copy reactor metadata first to maximize layer cache hit rate.
COPY pom.xml .
COPY vork-relay-lib/pom.xml vork-relay-lib/pom.xml
COPY vork-relay-server/pom.xml vork-relay-server/pom.xml

# Resolve dependencies before copying sources.
RUN mvn -q -pl vork-relay-server -am dependency:go-offline

COPY vork-relay-lib/src vork-relay-lib/src
COPY vork-relay-server/src vork-relay-server/src

RUN mvn -q -pl vork-relay-server -am -DskipTests -Dmaven.javadoc.skip=true package

FROM eclipse-temurin:21-jre

WORKDIR /app

RUN addgroup --system vork && adduser --system --ingroup vork vork

COPY --from=build /workspace/vork-relay-server/target/vork-relay.jar /app/vork-relay.jar

EXPOSE 8090

USER vork

ENTRYPOINT ["java", "-jar", "/app/vork-relay.jar"]
