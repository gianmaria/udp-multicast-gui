cmake_minimum_required(VERSION 3.16) # Qt 6 generally requires CMake 3.16+

project(MulticastReceiver LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) # Recommended for standard compliance

# --- Find Qt 6 ---
# You might need to set CMAKE_PREFIX_PATH if Qt is not in a standard location
# Example: cmake .. -DCMAKE_PREFIX_PATH=/path/to/your/Qt/6.x.x/msvcxxxx_64
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

# --- Enable Qt CMake Features ---
# Automatically run moc, uic, and rcc
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON) # Not strictly needed for this code, but good practice
set(CMAKE_AUTORCC ON) # Not strictly needed for this code, but good practice

# --- Define Executable ---
add_executable(MulticastReceiver
    main.cpp
    mainwindow.cpp
    mainwindow.h
)

# --- Link Qt Libraries ---
target_link_libraries(MulticastReceiver PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)

# --- Optional: Include Directories (often handled by find_package) ---
# target_include_directories(MulticastReceiver PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})


# --- MSVC Specific (Optional, usually handled) ---
if(MSVC)
    # Add definitions or flags specific to MSVC if needed
    # Example: target_compile_definitions(MulticastReceiver PRIVATE _UNICODE UNICODE WIN32)
    # Qt usually handles necessary defines like WIN32, _UNICODE, UNICODE
endif()

# --- Installation (Optional) ---
# If you plan to install the application
# install(TARGETS MulticastReceiver RUNTIME DESTINATION bin)
