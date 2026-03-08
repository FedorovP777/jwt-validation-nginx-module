cmake_minimum_required(VERSION 3.16)
project(nginx_jwt_validator C)

set(CMAKE_C_STANDARD 11)
find_package(OpenSSL REQUIRED)
set(CMAKE_BUILD_TYPE Debug)

include(FetchContent)

FetchContent_Declare(
        unity
        GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
        GIT_TAG v2.6.0
)

FetchContent_MakeAvailable(unity)

add_executable(tests tests/test_jwt.c ./jwt_validator.c jwt_validator.h)
target_include_directories(tests PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(tests PRIVATE unity OpenSSL::SSL OpenSSL::Crypto)

################################
# PVS-Studio
################################
if (NOT PROD_BUILD)
    include(./PVS-Studio.cmake)
    pvs_studio_add_target(TARGET pvs-studio ALL
            OUTPUT FORMAT errorfile
            ANALYZE ${PROJECT_NAME}
            MODE GA:1,2 OP
            LOG target.err)
endif()



#[[ Для локальной разработки. Что бы Clion синтаксис структур подсвечивал
add_executable(nginx_jwt_validator ngx_jwt_validator_module.c jwt_validator.c)
target_include_directories(nginx_jwt_validator PUBLIC
        /home/user/nginx-release-1.29.5/src/core/
        /home/user/nginx-release-1.29.5/src/http/
        /home/user/nginx-release-1.29.5/objs/
        /home/user/nginx-release-1.29.5/src/os/unix/
)
target_link_libraries(nginx_jwt_validator PRIVATE unity OpenSSL::SSL OpenSSL::Crypto)
]]


