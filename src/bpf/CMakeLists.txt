# Copyright 2024, Cisco Systems, Inc.

set(component_name se-ebpf-bpf)

if(is_arch_intel)
    set(se_ebpf_bpf_target_arch x86)
elseif(is_arch_arm)
    set(se_ebpf_bpf_target_arch arm64)
else()
    message(FATAL_ERROR "Failed to determine target arch")
endif()

set(vmlinux_include_dir ${CMAKE_CURRENT_SOURCE_DIR}/${se_ebpf_bpf_target_arch})

# List of src files to convert from c -> objects -> skeleton files.
set(src_files
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/file_close_write.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/file_create.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/file_delete.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/file_read.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/file_rename.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/file_write.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/kernel_features.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/network_accept.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/network_connect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/network_listen.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/network_receive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/network_release.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/network_send.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/process_exec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/process_exit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/probes/process_fork.c
)

set(skel_files "")

foreach(src_file ${src_files})
    get_filename_component(file ${src_file} NAME_WE)
    set(obj_file ${CMAKE_CURRENT_BINARY_DIR}/${file}.bpf.o)
    set(skel_file ${se_ebpf_install_dir}/${file}.skel.h)

    list(APPEND skel_files ${skel_file})

    add_custom_command(
        COMMAND ${CLANG} -O2 -g -target bpf -D__TARGET_ARCH_${se_ebpf_bpf_target_arch} -I${COMPONENT_INCLUDE_DIR} -I${vmlinux_include_dir} -I${se_ebpf_include_dir} -I${CMAKE_CURRENT_SOURCE_DIR} -c ${src_file} -o ${obj_file}
        DEPENDS
            ${src_file}
            ${se_ebpf_files}
            component-libbpf
            component-llvm
        OUTPUT ${obj_file}
    )

    add_custom_command(
        COMMAND ${BPFTOOL} gen skeleton ${obj_file} > ${skel_file}
        DEPENDS
            ${obj_file}
            component-bpftool
        OUTPUT ${skel_file}
    )
endforeach()

add_custom_target(${component_name}-generate-skel ALL
    DEPENDS ${skel_files}
)

add_library(${component_name} INTERFACE)

target_include_directories(${component_name} INTERFACE
    ${se_ebpf_install_dir}
    ${se_ebpf_include_dir}
)

add_dependencies(${component_name}
    ${component_name}-generate-skel
)
