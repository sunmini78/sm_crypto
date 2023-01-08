cmake_minimum_required(VERSION 3.14)

project(SM_CRYPTO DESCRIPTION "Crypto API " LANGUAGES C CXX)


set(CMAKE_C_STANDARD 99 CACHE STRING "The C standard to use")
set(CMAKE_CXX_STANDARD 14 CACHE STRING "The C++ standard to use")

set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-pthread -fPIC")
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-pthread")
# add_compile_options( -Wall -Wextra -pedantic -Werror)

include(FetchContent)
FetchContent_Declare(
	googletest
	URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
	)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

set(CRYPTOLIBRARY_MODE "" CACHE STRING "Choose the Library type of Cryto Library")
set_property(CACHE CRYPTOLIBRARY_MODE PROPERTY STRINGS "" OPENSSL)


if(NOT CRYPTOLIBRARY_MODE)
	set(CRYPTOLIBRARY_MODE "OPENSSL" CACHE STRING "Choose the sw type of cryptofunction." FORCE)
endif()

add_library(sm_crypto SHARED)
target_include_directories(sm_crypto PUBLIC include)

if( ${CRYPTOLIBRARY_MODE} STREQUAL "OPENSSL" )
	set(OPENSSL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include" CACHE STRING "OpenSSL include dir" FORCE)

	# if (BUILD_SHARED_LIBS)
	#   set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_SOURCE_DIR}/lib/libcrypto.so" CACHE STRING "OpenSSL crypto library" FORCE)
	#   set(OPENSSL_SSL_LIBRARY "${CMAKE_SOURCE_DIR}/lib/libssl.so" CACHE STRING "OpenSSL ssl library" FORCE)
	# else()
	set(OPENSSL_CRYPTO_LIBRARY "${CMAKE_SOURCE_DIR}/lib/libcrypto.a" CACHE STRING "OpenSSL crypto static library" FORCE)
	#  set(OPENSSL_SSL_LIBRARY "${CMAKE_SOURCE_DIR}//lib/libssl.a" CACHE STRING "OpenSSL ssl static library" FORCE)
	# endif()
	set(OPENSSL_LIBRARIES OPENSSL_SSL_LIBRARY OPENSSL_CRYPTO_LIBRARY CACHE STRING "OpenSSL libraries" FORCE)

	file(GLOB SRC_FILES  "src/openssl/*.c" )
	find_package(OpenSSL REQUIRED)
	target_link_libraries(sm_crypto PRIVATE  OpenSSL::Crypto)
else()
	set(MBEDTLS_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/include" CACHE STRING "MbedTLS include dir" FORCE)
	set(MBEDTLS_LIBRARIES "${CMAKE_SOURCE_DIR}/lib/libmbedcrypto.a" CACHE STRING "MbedTLS crypto static library" FORCE)
	file(GLOB SRC_FILES  "src/mbedtls/*.c" )
	# find_package(MbedTLS REQUIRED)
	target_link_libraries(sm_crypto PRIVATE ${MBEDTLS_LIBRARIES})
endif()

target_sources(sm_crypto PUBLIC ${SRC_FILES})

enable_testing()

file(GLOB TEST_SRC_FILES  "test/*.cpp" )

add_executable(crypto_test ${TEST_SRC_FILES})

target_link_libraries(
	crypto_test
	GTest::gtest_main
	sm_crypto
)

include(GoogleTest)
gtest_discover_tests(crypto_test)
