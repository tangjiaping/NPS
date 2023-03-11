
set(CMAKE_CXX_STANDARD 14)

add_executable(Test Test.cpp)
target_link_libraries(Test gtest_main gtest pthread gmock)

add_test(TARGET Test)