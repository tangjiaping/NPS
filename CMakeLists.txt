cmake_minimum_required(VERSION 3.23)
project(NPS)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(Qt5_DIR "/opt/qt/5.12.12/gcc_64/lib/")

add_subdirectory(test)

find_package(Qt5 COMPONENTS
        Core
        Gui
        Widgets
        REQUIRED)

add_executable(NPS main.cpp src/MainWindow.cpp include/MainWindow.h src/MainWidget.cpp include/MainWidget.h src/DataPkg.cpp include/DataPkg.h src/Sniffer.cpp include/Sniffer.h include/Protocol.h)
target_link_libraries(NPS
        Qt5::Core
        Qt5::Gui
        Qt5::Widgets
        pthread gmock -lpcap
        )

enable_testing()
