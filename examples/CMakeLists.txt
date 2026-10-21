# the examples on npf.h alone, linked with the shared library (as a vendor
# or an application builds them on the installed SDK: see device.c, client.c)
find_package(Threads REQUIRED)
add_executable(npf-device device.c)
target_link_libraries(npf-device PRIVATE npf_shared Threads::Threads)
npf_target_options(npf-device)
add_executable(npf-client client.c)
target_link_libraries(npf-client PRIVATE npf_shared Threads::Threads)
npf_target_options(npf-client)
