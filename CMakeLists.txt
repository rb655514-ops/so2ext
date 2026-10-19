cmake_minimum_required(VERSION 3.18)
project(so2ext CXX)
set(CMAKE_CXX_STANDARD 17)
add_executable(so2ext tools/recon.cpp)
target_link_libraries(so2ext PRIVATE psapi)22:43
