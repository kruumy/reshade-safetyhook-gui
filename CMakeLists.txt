cmake_minimum_required(VERSION 3.16)

project(reshade-safetyhook-gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(${PROJECT_NAME} SHARED
    # @glob("src/**/*.{cpp,c}")
    "src/dllmain.cpp"
    "src/memory_utils.cpp"
    "src/midhook_wrapper.cpp"
    "src/pointer_analysis.cpp"
    # @end
)

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".addon32")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".addon64")
endif()

include(FetchContent)

# Safetyhook
set(SAFETYHOOK_FETCH_ZYDIS ON)
FetchContent_Declare(
    safetyhook
    GIT_REPOSITORY "https://github.com/cursey/safetyhook.git"
    GIT_TAG "origin/main"
)
FetchContent_MakeAvailable(safetyhook)
target_link_libraries(${PROJECT_NAME} PRIVATE safetyhook)

# imgui
add_library(imgui INTERFACE)
target_include_directories(imgui INTERFACE external/reshade/deps/imgui)
target_link_libraries(${PROJECT_NAME} PRIVATE imgui)

# reshade
add_library(reshade INTERFACE)
target_include_directories(reshade INTERFACE external/reshade/include)
target_link_libraries(${PROJECT_NAME} PRIVATE reshade)
