#include <rte_bus_pci.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_pci.h>

#include "mempool.h"

#define HW_RXCSUM 0
#define HW_TXCSUM 0
#define MIN(a, b) ((a) < (b) ? (a) : (b))
static const struct rte_eth_conf default_eth_conf = {
    .link_speeds = ETH_LINK_SPEED_AUTONEG, /* auto negotiate speed */
    /*.link_duplex = ETH_LINK_AUTONEG_DUPLEX,	[> auto negotiation duplex <]*/
    .lpbk_mode = 0,
    .rxmode =
        {
            .mq_mode        = ETH_MQ_RX_NONE, /* Disable RSS, DCB or VMDQ */
            .max_rx_pkt_len = 0,              /* valid only if jumbo is on */
            .split_hdr_size = 0,              /* valid only if HS is on */
            .split_hdr_size = 0,              /* Header Split off */
            .offloads       = 0,              /* No offload */
            .max_rx_pkt_len = 0,              /* Maximum packet length */
        },
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE, /* Disable DCB and VMDQ */
        },
    .fdir_conf =
        {
            .mode    = RTE_FDIR_MODE_PERFECT,
            .pballoc = RTE_FDIR_PBALLOC_64K,
        },
    /* No interrupt */
    .intr_conf =
        {
            .lsc = 0,
        },
};

int num_pmd_ports() {
    return rte_eth_dev_count_avail();
}

int get_pmd_ports(struct rte_eth_dev_info* info, int len) {
    int num_ports   = num_pmd_ports();
    int num_entries = MIN(num_ports, len);
    for (int i = 0; i < num_entries; i++) {
        memset(&info[i], 0, sizeof(struct rte_eth_dev_info));
        rte_eth_dev_info_get(i, &info[i]);
    }
    return num_entries;
}

int get_rte_eth_dev_info(int dev, struct rte_eth_dev_info* info) {
    if (dev >= num_pmd_ports()) {
        return -ENODEV;
    } else {
        rte_eth_dev_info_get(dev, info);
        return 0;
    }
}

int max_rxqs(int dev) {
    struct rte_eth_dev_info info;
    if (get_rte_eth_dev_info(dev, &info) != 0) {
        return -ENODEV;
    } else {
        return info.max_rx_queues;
    }
}

int max_txqs(int dev) {
    struct rte_eth_dev_info info;
    if (get_rte_eth_dev_info(dev, &info) != 0) {
        return -ENODEV;
    } else {
        return info.max_tx_queues;
    }
}

void enumerate_pmd_ports() {
    int num_dpdk_ports = num_pmd_ports();
    int i;

    printf("%d DPDK PMD ports have been recognized:\n", num_dpdk_ports);
    for (i = 0; i < num_dpdk_ports; i++) {
        struct rte_eth_dev_info dev_info;
        const struct rte_pci_device* pci_dev;

        memset(&dev_info, 0, sizeof(dev_info));
        rte_eth_dev_info_get(i, &dev_info);

        printf("DPDK port_id %d (%s)   RXQ %hu TXQ %hu  ", i, dev_info.driver_name,
               dev_info.max_rx_queues, dev_info.max_tx_queues);

        pci_dev = RTE_DEV_TO_PCI(dev_info.device);
        if (pci_dev) {
            printf("%04x:%02hhx:%02hhx.%02hhx %04hx:%04hx  ", pci_dev->addr.domain, pci_dev->addr.bus,
                   pci_dev->addr.devid, pci_dev->addr.function, pci_dev->id.vendor_id, pci_dev->id.device_id);
        }

        printf("\n");
    }
}

static int log_eth_dev_info(struct rte_eth_dev_info* dev_info) {
    if (!dev_info)
        return -1;
    RTE_LOG(INFO, PMD, "driver_name: %s (if_index: %d)\n", dev_info->driver_name, dev_info->if_index);
    RTE_LOG(INFO, PMD, "max_rx_queues / nb_rx_queue: %d / %d\n", dev_info->max_rx_queues, dev_info->nb_rx_queues);
    RTE_LOG(INFO, PMD, "max_tx_queues / nb_tx_queue : %d / %d\n", dev_info->max_tx_queues, dev_info->nb_tx_queues);
    RTE_LOG(INFO, PMD, "rx_offload_capa: %lx\n", dev_info->rx_offload_capa);
    RTE_LOG(INFO, PMD, "rx_queue_offload_capa: %lx\n", dev_info->rx_queue_offload_capa);
    RTE_LOG(INFO, PMD, "tx_offload_capa: %lx\n", dev_info->tx_offload_capa);
    RTE_LOG(INFO, PMD, "tx_queue_offload_capa: %lx\n", dev_info->tx_queue_offload_capa);
    RTE_LOG(INFO, PMD, "flow_type_rss_offloads: %lx\n\n", dev_info->flow_type_rss_offloads);
    return 0;
}

static int log_eth_rxconf(struct rte_eth_rxconf* rxconf) {
    if (!rxconf)
        return -1;
    RTE_LOG(INFO, PMD, "rx_thresh (p,h,w): (%d, %d, %d)\n", rxconf->rx_thresh.pthresh,
            rxconf->rx_thresh.hthresh, rxconf->rx_thresh.wthresh);
    RTE_LOG(INFO, PMD, "rx_free_thresh: %d\n", rxconf->rx_free_thresh);
    RTE_LOG(INFO, PMD, "rx_drop_en: %d\n", rxconf->rx_drop_en);
    RTE_LOG(INFO, PMD, "rx_deferred_start: %d\n", rxconf->rx_deferred_start);
    RTE_LOG(INFO, PMD, "rx_offloads: 0x%lx\n\n", rxconf->offloads);

    return 0;
}

static int log_eth_txconf(struct rte_eth_txconf* txconf) {
    if (!txconf)
        return -1;
    RTE_LOG(INFO, PMD, "tx_thresh (p,h,w): (%d, %d, %d)\n", txconf->tx_thresh.pthresh,
            txconf->tx_thresh.hthresh, txconf->tx_thresh.wthresh);
    RTE_LOG(INFO, PMD, "tx_free_thresh: %d\n", txconf->tx_free_thresh);
    RTE_LOG(INFO, PMD, "tx_rs_thresh: %d\n", txconf->tx_rs_thresh);
    RTE_LOG(INFO, PMD, "tx_deferred_start: %d\n", txconf->tx_deferred_start);
    RTE_LOG(INFO, PMD, "tx_offloads: 0x%lx\n", txconf->offloads);

    return 0;
}

int init_pmd_port(int port, int rxqs, int txqs, int rxq_core[], int txq_core[], int nrxd, int ntxd,
                  int loopback, int tso, int csumoffload) {
    struct rte_eth_dev_info dev_info = {};
    struct rte_eth_conf eth_conf;
    struct rte_eth_rxconf eth_rxconf;
    struct rte_eth_txconf eth_txconf;
    int ret, i;

    /* Need to accesss rte_eth_devices manually since DPDK currently
     * provides no other mechanism for checking whether something is
     * attached */
    if (port >= RTE_MAX_ETHPORTS || rte_eth_devices[port].state != RTE_ETH_DEV_ATTACHED) {
        printf("Port not found %d\n", port);
        return -ENODEV;
    }

    eth_conf           = default_eth_conf;
    eth_conf.lpbk_mode = !(!loopback);

    /* Use defaut rx/tx configuration as provided by PMD drivers,
     * with minor tweaks */
    rte_eth_dev_info_get(port, &dev_info);

    eth_rxconf = dev_info.default_rxconf;
    if (strcmp(dev_info.driver_name, "rte_em_pmd") != 0 &&
        strcmp(dev_info.driver_name, "net_e1000_em") != 0) {
        /* Drop packets when no descriptors are available
         * Protected since this is not supported by EM driver
         * and there is no convenient way to look this up in DPDK. */
        eth_rxconf.rx_drop_en = 1;
    }

    eth_txconf  = dev_info.default_txconf;
    tso         = !(!tso);
    csumoffload = !(!csumoffload);

    if (csumoffload) {
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) {
            eth_txconf.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
            eth_conf.txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
        }
        if (dev_info.rx_offload_capa & (DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_KEEP_CRC)) {
            eth_rxconf.offloads |= DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_KEEP_CRC;
            eth_conf.rxmode.offloads |= DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_KEEP_CRC;
        }
    }
    // eth_txconf.txq_flags = ETH_TXQ_FLAGS_NOVLANOFFL | ETH_TXQ_FLAGS_NOMULTSEGS * (1 - tso) |
    //                        ETH_TXQ_FLAGS_NOXSUMS * (1 - csumoffload);

    ret = rte_eth_dev_configure(port, rxqs, txqs, &eth_conf);
    if (ret != 0) {
        return ret; /* Don't need to clean up here */
    }

    rte_eth_dev_info_get(port, &dev_info);
    RTE_LOG(INFO, PMD, "--- rte_eth_dev_info:\n");
    log_eth_dev_info(&dev_info);
    RTE_LOG(INFO, PMD, "--- using eth_rxconf:\n");
    log_eth_rxconf(&eth_rxconf);
    RTE_LOG(INFO, PMD, "--- using eth_txconf:\n");
    log_eth_txconf(&eth_txconf);

    /* Set to promiscuous mode */
    rte_eth_promiscuous_disable(port);
    ret = rte_eth_promiscuous_get(port);
    RTE_LOG(INFO, PMD, "Promiscuous mode is %s\n\n", ret == 0 ? "disabled" : "enabled");

    for (i = 0; i < rxqs; i++) {
        int sid = rte_lcore_to_socket_id(rxq_core[i]);
        ret = rte_eth_rx_queue_setup(port, i, nrxd, sid, &eth_rxconf, get_pframe_pool(rxq_core[i], sid));
        if (ret != 0) {
            printf("Failed to initialize rxq\n");
            return ret; /* Clean things up? */
        }
    }

    for (i = 0; i < txqs; i++) {
        int sid = rte_lcore_to_socket_id(txq_core[i]);

        ret = rte_eth_tx_queue_setup(port, i, ntxd, sid, &eth_txconf);
        if (ret != 0) {
            printf("Failed to initialize txq\n");
            return ret; /* Clean things up */
        }
    }

    ret = rte_eth_dev_start(port);
    if (ret != 0) {
        printf("Failed to start \n");
        return ret; /* Clean up things */
    }

    // TODO: This is a hack to get around the fact that the net_pcap driver
    // does not support FDIR.
    if (strcmp(dev_info.driver_name, "net_pcap") == 0) {
        eth_conf.fdir_conf.mode = RTE_FDIR_MODE_NONE;
        return 0;
    }

    /* Flow director setup */
    int retval = 0;

    /*
     * First, setup details regarding the flow to be filtered. Restrict to
     * IP+UDP packets, and look at only the UDP destination port.
     */
    struct rte_eth_fdir_filter_info filter_info;
    memset(&filter_info, 0, sizeof(filter_info));
    filter_info.info_type                      = RTE_ETH_FDIR_FILTER_INPUT_SET_SELECT;
    filter_info.info.input_set_conf.flow_type  = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
    filter_info.info.input_set_conf.inset_size = 1;
    filter_info.info.input_set_conf.field[0]   = RTE_ETH_INPUT_SET_L4_UDP_DST_PORT;
    filter_info.info.input_set_conf.op         = RTE_ETH_INPUT_SET_SELECT;
    retval = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_SET, &filter_info);
    if (retval != 0) {
        rte_exit(EXIT_FAILURE, "Could not set fdir info: %s\n", strerror(-retval));
    }

    /*
     * Next, configure a rule for each receive queue. Redirect packets with UDP
     * destination port 'i' to receive queue 'i'.
     */
    for (i = 0; i < rxqs; i++) {
        struct rte_eth_fdir_filter fdirf;
        memset(&fdirf, 0, sizeof(fdirf));
        fdirf.soft_id                       = i;
        fdirf.input.flow_type               = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
        fdirf.input.flow.udp4_flow.dst_port = rte_cpu_to_be_16(i);
        fdirf.action.rx_queue               = i;
        fdirf.action.behavior               = RTE_ETH_FDIR_ACCEPT;
        fdirf.action.report_status          = RTE_ETH_FDIR_NO_REPORT_STATUS;
        retval = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_ADD, &fdirf);
        if (retval != 0) {
            rte_exit(EXIT_FAILURE, "Could not add fdir UDP filter: %s\n", strerror(-retval));
        }
    }

    return 0;
}

void free_pmd_port(int port) {
    rte_eth_dev_stop(port);
    rte_eth_dev_close(port);
}

int recv_pkts(int port, int qid, mbuf_array_t pkts, int len) {
    int ret = rte_eth_rx_burst(port, qid, (struct rte_mbuf**)pkts, len);
/* Removed prefetching since the benefit in performance for single core was
 * outweighed by the loss in performance with several cores. */
#if 0
    for (int i = 0; i < ret; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void*));
    }
#endif
    return ret;
}

int send_pkts(int port, int qid, mbuf_array_t pkts, int len) {
    return rte_eth_tx_burst(port, (uint16_t)qid, (struct rte_mbuf**)pkts, (uint16_t)len);
}

int find_port_with_pci_address(const char* pci) {
    struct rte_pci_addr addr;
    char devargs[1024];
    uint16_t pi;
    uint8_t port;
    struct rte_dev_iterator iterator;
    int max_queues = 0;

    // Cannot parse address
    if (rte_pci_addr_parse(pci, &addr) != 0) {
        return -1;
    }

    int n_devices = num_pmd_ports();
    for (int i = 0; i < n_devices; i++) {
        struct rte_eth_dev_info dev_info;
        struct rte_pci_device* pci_dev;

        rte_eth_dev_info_get(i, &dev_info);
        max_queues = dev_info.max_rx_queues > max_queues ? dev_info.max_rx_queues : max_queues;
        pci_dev    = RTE_DEV_TO_PCI(dev_info.device);

        if (pci_dev) {
            if (rte_pci_addr_cmp(&addr, &pci_dev->addr)) {
                return i;
            }
        }
    }

    /* If not found, maybe the device has not been attached yet */
    snprintf(devargs, 1024, "%04x:%02x:%02x.%02x", addr.domain, addr.bus, addr.devid, addr.function);

    uint16_t portid_ptr[max_queues];
    uint16_t* ptr;
    ptr       = portid_ptr;
    int count = 0;

    RTE_ETH_FOREACH_MATCHING_DEV(pi, devargs, &iterator) {
        /* setup ports matching the devargs used for probing */
        *ptr = pi;
        ptr++;
        count++;
        if (count >= max_queues)
            break;
    }
    if (count == 0) {
        return -ENODEV;
    }
    port = portid_ptr[0];
    return (int)port;
}

/* Attach a device with a given name (useful when attaching virtual devices). Returns either the
   port number of the
   device or an error if not found. */
int attach_pmd_device(const char* devname) {
    uint8_t port = 0;
    uint16_t pi;
    struct rte_dev_iterator iterator;

    if (devname == NULL) {
        RTE_LOG(WARNING, PMD, "attach_port: null pointers not allowed\n");
        return -1;
    }
    RTE_LOG(WARNING, PMD, "trying to attach device %s\n", devname);

    if (rte_dev_probe(devname) != 0) {
        RTE_LOG(WARNING, PMD, "Failed to attach device %s\n", devname);
        return -ENODEV;
    }

    uint16_t portid_ptr[16];
    uint16_t* ptr;
    ptr       = portid_ptr;
    int count = 0;

    RTE_ETH_FOREACH_MATCHING_DEV(pi, devname, &iterator) {
        /* setup ports matching the devargs used for probing */
        *ptr = pi;
        ptr++;
        count++;
        if (count >= 16)
            break;
    }
    if (count == 0) {
        return -ENODEV;
    }
    port = portid_ptr[0];
    return (int)port;
}

/* FIXME: Add function to modify RSS hash function using
 * rte_eth_dev_rss_hash_update */
