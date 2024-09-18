# Copyright 2024, Cisco Systems, Inc.

set(se_ebpf_install_dir ${COMPONENT_INCLUDE_DIR}/se-ebpf)
set(se_ebpf_include_dir ${SE_EBPF_DIR}/include)
file(GLOB_RECURSE se_ebpf_files "*.h" )

add_subdirectory(bcc)
add_subdirectory(bpf)
