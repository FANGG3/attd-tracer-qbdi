cmake_minimum_required(VERSION 3.22.1)

# Setting Android Build
set(CMAKE_SYSTEM_NAME ANDROID)
set(CMAKE_SYSTEM_VERSION 28)
set(ANDROID_PLATFORM 28)
set(ANDROID_ABI arm64-v8a)

if(DEFINED ENV{ANDROID_NDK})
        set(ANDROID_NDK $ENV{ANDROID_NDK})
endif ()

if(NOT DEFINED ANDROID_NDK)
        message(FATAL_ERROR "Please Set NDK PATH: cmake .. -DANDROID_NDK=\"YOUR_PATH\"")
endif ()
set(CMAKE_TOOLCHAIN_FILE ${ANDROID_NDK}/build/cmake/android.toolchain.cmake)
# End Setting Android Build

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_BUILD_TYPE "RELEASE")

# 优化编译选项
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -ffast-math -march=armv8-a+crypto -mtune=cortex-a75 -flto -fomit-frame-pointer -funroll-loops -fno-stack-protector")
add_compile_definitions(ULTRA_FAST_MODE=1)



project("attd")
set(HOME ${PROJECT_SOURCE_DIR})
include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/
)

FILE(GLOB_RECURSE FILE_SOURCES # 遍历子目录下所有符合情况的源文件
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c*
)
add_library(${CMAKE_PROJECT_NAME} SHARED
        ${FILE_SOURCES}
        library.cpp
        )

add_library(${CMAKE_PROJECT_NAME}_static STATIC
        ${FILE_SOURCES}
        library.cpp
)

# Setting libs
add_library(QBDIAARCH64 STATIC IMPORTED)
set_target_properties(QBDIAARCH64 PROPERTIES IMPORTED_LOCATION
        ${PROJECT_SOURCE_DIR}/libs/QBDI-aarch64/libQBDI.a)


add_library(frida-gum-arm64 STATIC IMPORTED)
set_target_properties(frida-gum-arm64 PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/libs/frida-gum/libfrida-gum.a)


#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
set(CMAKE_BUILD_TYPE "debug")
#set(CMAKE_BUILD_TYPE "RELEASE")

#set(CMAKE_CXX_VISIBILITY_PRESET hidden)
#set(CMAKE_C_VISIBILITY_PRESET hidden)

## 关闭C++特性set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-inline")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
#
#set(CMAKE_C_FLAGS_RELEASE     "${CMAKE_C_FLAGS_RELEASE}   -fvisibility=hidden")
#set(CMAKE_CXX_FLAGS_RELEASE   "${CMAKE_CXX_FLAGS_RELEASE} -fvisibility=hidden")
## 删除调试符号
#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")
## 开启空间优化
#set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Os")
#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os")

target_link_options(${CMAKE_PROJECT_NAME} PRIVATE -Wl,--exclude-libs=ALL)

target_link_libraries(${CMAKE_PROJECT_NAME}_static PUBLIC

        frida-gum-arm64
        QBDIAARCH64

        android
        log)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE

        frida-gum-arm64
        QBDIAARCH64

        android
        log)

add_executable(${CMAKE_PROJECT_NAME}_test
        ${FILE_SOURCES}
        test/test.cpp
)

target_link_libraries(${CMAKE_PROJECT_NAME}_test
        ${CMAKE_PROJECT_NAME}_static
)
