#include <rte_config.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_ethdev.h>

// Make rte_hash_crc available to Rust. This adds some cost, will look into producing a pure Rust
// version.
uint32_t crc_hash_native(const void* data, uint32_t len, uint32_t initial) {
    return rte_hash_crc(data, len, initial);
}

uint16_t ipv4_cksum(const void* iphdr) {
    return rte_ipv4_cksum((const struct rte_ipv4_hdr*)iphdr);
}

int get_mac_address(uint16_t port_id, struct rte_ether_addr* mac_addr) {
    return rte_eth_macaddr_get(port_id, mac_addr);
}
