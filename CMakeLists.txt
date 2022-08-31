cmake_minimum_required(VERSION 3.23)
project(LearningCrypto)

set(CMAKE_CXX_STANDARD 20)

add_executable(LearningCrypto main.cpp openssl.cpp  )
target_link_libraries(LearningCrypto crypto ssl)
