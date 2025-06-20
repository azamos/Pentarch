cmake_minimum_required(VERSION 3.15)
project(CppSysmonServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Collect source files
file(GLOB SOURCES "server/*.cpp")
file(GLOB HEADERS "server/*.h")

# Create the executable
add_executable(server ${SOURCES} ${HEADERS})

# Include sqlite and server headers
target_include_directories(server PRIVATE server third_party/sqlite)

# Link against sqlite3 static lib and Winsock
target_link_libraries(server PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/sqlite/libsqlite3.a
    ws2_32
)
