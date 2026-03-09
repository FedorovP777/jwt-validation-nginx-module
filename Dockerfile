FROM alpine:latest
RUN apk update
RUN apk add wget git build-base openssl-dev pcre2-dev
RUN git clone https://github.com/FedorovP777/jwt-validation-nginx-module.git
RUN wget -O nginx.tar.gz 'https://github.com/nginx/nginx/archive/refs/tags/release-1.29.6.tar.gz'
RUN mkdir nginx-src && tar -xzf ./nginx.tar.gz -C nginx-src --strip-components=1
WORKDIR nginx-src
RUN ./auto/configure --with-http_ssl_module --add-module=../jwt-validation-nginx-module/src/
RUN make && make install
ENTRYPOINT ["/usr/local/nginx/sbin/nginx" , "-c", "/jwt-validation-nginx-module/nginx.conf"]