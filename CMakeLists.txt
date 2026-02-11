cmake_minimum_required(VERSION 3.20)

project(reshade-safetyhook-gui LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(reshade INTERFACE)
target_include_directories(reshade INTERFACE external/reshade/include )

add_library(imgui INTERFACE)
target_include_directories(imgui INTERFACE external/reshade/deps/imgui)

add_library(${PROJECT_NAME} SHARED
# @glob("src/**/*.{cpp,c}")
  "src/dllmain.cpp"
  "src/memory_utils.cpp"
  "src/midhook_wrapper.cpp"
  "src/pointer_analysis.cpp"
# @end
)

target_link_libraries(${PROJECT_NAME} PRIVATE reshade imgui)

if (CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".addon32")
elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".addon64")
endif()
