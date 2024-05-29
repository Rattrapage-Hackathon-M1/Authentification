FROM eclipse-temurin:21

WORKDIR /app

COPY .mvn/ .mvn
COPY mvnw pom.xml ./
RUN sed -i 's/\r$//' mvnw
RUN chmod +x mvnw
RUN ./mvnw dependency:resolve

COPY src ./src
RUN ./mvnw package -DskipTests

EXPOSE 8080

CMD ["./mvnw", "spring-boot:run"]