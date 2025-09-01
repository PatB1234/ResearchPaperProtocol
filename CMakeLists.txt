cmake_minimum_required(VERSION 3.16)
project(ProtocolOpenFHE)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the include root (so compiler can resolve pke/openfhe.h)
include_directories(/usr/local/include/openfhe)
include_directories(/usr/local/include/openfhe/core)
include_directories(/usr/local/include/openfhe/pke)
include_directories(/usr/local/include/openfhe/binfhe)
include_directories(/usr/local/include/openfhe/cereal)


# Tell linker where to find OpenFHE .dylib files
link_directories(/usr/local/lib)

add_executable(ProtocolOpenFHE client.cpp
        server.cpp
        server.h
        client.h
        master.cpp
        master.h
)

# Link the OpenFHE libraries you have installed
target_link_libraries(ProtocolOpenFHE
        PRIVATE
        OPENFHEcore
        OPENFHEpke
        OPENFHEbinfhe
)
