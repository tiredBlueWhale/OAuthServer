FROM maven:3-jdk-8 as builder

COPY . /tmp/pattern-pedia-auth
WORKDIR /tmp/pattern-pedia-auth
RUN mvn package -DskipTests

FROM openjdk:8

ARG DOCKERIZE_VERSION=v0.6.1

ENV AUTH_PORT 8081
ENV JDBC_DATABASE_URL localhost
ENV JDBC_DATABASE_USERNAME postgres
ENV JDBC_DATABASE_PASSWORD postgres
ENV JDBC_DATABASE_NAME postgres
ENV JDBC_DATABASE_PORT 5432

RUN wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && tar -C /usr/local/bin -xzvf dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && rm dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz

EXPOSE ${AUTH_PORT}
COPY --from=builder /tmp/pattern-pedia-auth/target/auth-0.0.1-SNAPSHOT.jar /var/www/java/auth.jar

ADD .docker/application.properties.tpl /var/www/java/application.properties.tpl

CMD  dockerize -template /var/www/java/application.properties.tpl:/var/www/java/application.properties \
     && cd /var/www/java/ \
     && java -jar auth.jar
