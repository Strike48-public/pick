cmake_minimum_required(VERSION 3.22.1)
project(pickcrux_jni C)

# The prebuilt crux FFI shared lib, produced by:
#   nix develop --command just crux-ffi-android-x86_64
# and copied into app/src/main/jniLibs/<abi>/libpick_crux_ffi.so
add_library(pick_crux_ffi SHARED IMPORTED)
set_target_properties(pick_crux_ffi PROPERTIES
    IMPORTED_LOCATION
    ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libpick_crux_ffi.so)

add_library(pickcrux_jni SHARED jni_bridge.c)

target_link_libraries(pickcrux_jni
    pick_crux_ffi
    log)
