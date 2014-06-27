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
#include "ds3pktccf.h"

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

inline ds3_packet_buffer_nbsmac_t::~ds3_packet_buffer_nbsmac_t() {}

/** @brief packet class for testing fake mac */
class ds3packet_nbsmac_t : public ds3packet_t {
public:
#if CCFDEBUG
    virtual void dump (void);
    virtual uint8_t & at(size_t i);
#endif
    ds3packet_nbsmac_t() { memset (&(this->machdr), 0, sizeof (this->machdr)); }
    virtual ~ds3packet_nbsmac_t() { std::cout << "Destroy " << __func__ << std::endl;}

    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (ds3_packet_buffer_t *peer, size_t pos_peer);

    /* OUT */
    virtual ds3_packet_buffer_t * insert_to (size_t pos_peer, ds3_packet_buffer_t *peer, size_t begin_self, size_t end_self);

    size_t gethdr_sequence () { return machdr.sequence; }

    /* IN */
    void sethdr_sequence (size_t seq) { machdr.sequence = seq; }
    virtual int set_content (ds3_packet_buffer_t *peer)
        { if (0 > ds3packet_t::set_content(peer)) { return -1; } this->get_header(); return 0; }

    bool operator == (const ds3packet_nbsmac_t & rhs) const ; /**< check if two ns2 packets are identical */
    bool operator != (const ds3packet_nbsmac_t & rhs) { return ! (*this == rhs); } /**< check if two ns2 packets are not identical */

private:
    int set_header (ds3hdr_mac_t * mhdr) { if (NULL == mhdr) {return -1;} memmove (&(this->machdr), mhdr, sizeof (*mhdr)); return 0; } /**< set the NS2 packet header */
    ds3hdr_mac_t & get_header (void) { this->machdr.length = this->get_content_ref().size(); return machdr; } /**< get a reference of the MAC header */

    ssize_t hdr_to_nbs (uint8_t *nbsbuf, size_t szbuf) { this->get_header(); return ds3hdr_mac_to_nbs (nbsbuf, szbuf, &(this->machdr)); }
    ds3hdr_mac_t machdr; /**< the MAC packet header */
    uint8_t machdrbuf[4]; /**< buffer for MAC header */
};

#if CCFDEBUG
int test_machdr (void);
#endif

#endif /* _TESTMAC_H */

