cmake_minimum_required(VERSION 3.16)
project(nginx_jwt_validator C)

set(CMAKE_C_STANDARD 11)
find_package(OpenSSL REQUIRED)
set(CMAKE_BUILD_TYPE Debug)


#[[ Для локальной разработки. Что бы Clion синтаксис структур подсвечивал
add_executable(nginx_jwt_validator ngx_jwt_validation.c)
target_include_directories(nginx_jwt_validator PUBLIC
        /home/user/nginx-release-1.29.5/src/core/
        /home/user/nginx-release-1.29.5/src/http/
        /home/user/nginx-release-1.29.5/objs/
        /home/user/nginx-release-1.29.5/src/os/unix/
)
target_link_libraries(nginx_jwt_validator PRIVATE unity OpenSSL::SSL OpenSSL::Crypto)
#]]


