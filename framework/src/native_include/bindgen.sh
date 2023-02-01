#!/bin/bash
bindgen --no-layout-tests --blocklist-type max_align_t dpdk-headers.h -o dpdk_bindings.rs