FROM eclipse-temurin:17-jdk-jammy

RUN apt-get update && apt-get install -y netcat && apt-get clean

WORKDIR /app

COPY target/authentication-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]