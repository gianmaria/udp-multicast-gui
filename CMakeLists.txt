cmake_minimum_required(VERSION 3.16) # Qt 6 generally requires CMake 3.16+

project(MulticastReceiver LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) # Recommended for standard compliance

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Add the WIN32 keyword here for /SUBSYSTEM:WINDOWS
add_executable(MulticastReceiver WIN32
    main.cpp
    mainwindow.cpp
    mainwindow.h
)

target_link_libraries(MulticastReceiver PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)
