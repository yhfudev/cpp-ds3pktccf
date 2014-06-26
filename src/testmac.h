/**
 * @file    testmac.h
 * @brief   fake mac for testing
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-19
 * @copyright Yunhui Fu (2014)
 */
#ifndef _TESTMAC_H
#define _TESTMAC_H

#include "ds3pktcnt.h"

#if 1
/**
 * @brief The DOCSIS MAC header structure
 */
typedef struct _ds3hdr_mac_t {
    uint16_t sequence; /**< The sequence # of the MAC packet */
    uint16_t length; /**< The length of the data in the MAC packet */
} ds3hdr_mac_t;

ssize_t ds3hdr_mac_to_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_mac_t * refhdr);
ssize_t ds3hdr_mac_from_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_mac_t * rethdr);
#endif

/**
 * @brief the packet content class for network byte sequence buffer of type DOCSIS MAC
 */
class ds3_packet_buffer_nbsmac_t : public ds3_packet_buffer_nbs_t {
public:
    ds3_packet_buffer_nbsmac_t() {}
    virtual ssize_t block_size_at (size_t pos);
    DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS_MINI(ds3_packet_buffer_nbsmac_t);
};

inline ds3_packet_buffer_nbsmac_t::ds3_packet_buffer_nbsmac_t(ds3_packet_buffer_t *peer, size_t begin, size_t end)
    : ds3_packet_buffer_nbs_t (peer, begin, end) { }

#if CCFDEBUG
int test_machdr (void);
#endif

#endif /* _TESTMAC_H */

