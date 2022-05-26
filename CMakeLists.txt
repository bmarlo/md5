cmake_minimum_required(VERSION 3.10)

project(md5)

function(cpp17 target)
    set_target_properties(${target}
        PROPERTIES
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
    )

    target_compile_options(${target}
        PRIVATE
            -Wall -Wextra -Wconversion -pedantic -Wno-sign-conversion
    )
endfunction()

add_library(md5 STATIC src/md5.cpp)
cpp17(md5)
target_include_directories(md5 PUBLIC include)

add_executable(strsum examples/strsum.cpp)
cpp17(strsum)
target_link_libraries(strsum md5)
