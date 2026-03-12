Example config

```
http {

    access_log /dev/stdout;

    server {
        listen       1086;
        server_name  localhost;
        location /test {
           jwt_validation_enable on;
           jwt_token_param "$http_authorization";
           jwt_token_param_second "$arg_token";
           jwt_token_secret 'JWT TEST 123';
           proxy_pass http://google.com;
        }

        location /test1 {
           proxy_pass http://google.com;
        }
    }
}
```