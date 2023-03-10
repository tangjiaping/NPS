cmake_minimum_required(VERSION 3.23)
project(NPS)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(Qt5_DIR "/opt/qt/5.12.12/gcc_64/lib/")

find_package(Qt5 COMPONENTS
        Core
        Gui
        Widgets
        REQUIRED)

add_executable(NPS main.cpp)
target_link_libraries(NPS
        Qt5::Core
        Qt5::Gui
        Qt5::Widgets
        )

