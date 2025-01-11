cmake_minimum_required(VERSION 3.10)
project(Facekid)

add_library(facekid STATIC src/facekid.c)
target_include_directories(facekid PUBLIC include)