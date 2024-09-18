# Copyright 2024, Cisco Systems, Inc.

set(component_name se-ebpf-bcc)

set(ebpf_file_proc_input
    ${CMAKE_CURRENT_SOURCE_DIR}/SeEbpfFileProcProgram.c
)
set(ebpf_network_input
    ${CMAKE_CURRENT_SOURCE_DIR}/SeEbpfNetworkMonitorProgram.c
)
set(ebpf_string_conversion_inputs
    ${ebpf_file_proc_input}
    ${ebpf_network_input}
)

set(ebpf_file_proc_output
    ${se_ebpf_install_dir}/SeEbpfFileProcProgram.frag
)
set(ebpf_network_output
    ${se_ebpf_install_dir}/SeEbpfNetworkMonitorProgram.frag
)
set(ebpf_string_conversion_outputs
    ${ebpf_file_proc_output}
    ${ebpf_network_output}
)

add_custom_command(
    OUTPUT ${ebpf_string_conversion_outputs}
    COMMAND ${CMAKE_COMMAND} -D INPUT_FILE=${ebpf_file_proc_input} -D OUTPUT_FILE=${ebpf_file_proc_output} -P ${CUSTOM_CMAKE_MODULE_PATH}/helper/ebpf_string_conversion_script.cmake
    COMMAND ${CMAKE_COMMAND} -D INPUT_FILE=${ebpf_network_input} -D OUTPUT_FILE=${ebpf_network_output} -P ${CUSTOM_CMAKE_MODULE_PATH}/helper/ebpf_string_conversion_script.cmake
    DEPENDS ${ebpf_string_conversion_inputs}
)

add_custom_target(
    ${component_name}-generate-frag ALL
    DEPENDS ${ebpf_string_conversion_outputs}
)

add_library(${component_name} INTERFACE)

target_include_directories(${component_name} INTERFACE
    ${se_ebpf_install_dir}
    ${se_ebpf_include_dir}
)

add_dependencies(${component_name}
    ${component_name}-generate-frag
)
