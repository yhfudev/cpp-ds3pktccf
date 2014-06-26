/**
 * @file    ds3ccfns2.h
 * @brief   CCF class for NS2 DOCSIS module
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-19
 * @copyright Yunhui Fu (2014)
 */

#ifndef _NS2CCF_H
#define _NS2CCF_H

#include "ds3pktccf.h"

/**
 * @brief the packet content class for NS2 Packet class
 */
class ds3_packet_buffer_ns2_t : public ds3_packet_buffer_t {
public:
#if CCFDEBUG
    virtual void dump (void);
#endif
    ds3_packet_buffer_ns2_t() {}

    virtual uint8_t & at(size_t i);
    virtual ssize_t block_size_at (size_t pos);
    DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS(ds3_packet_buffer_ns2_t);
};

/** @brief packet class for NS2 Packet */
class ds3packet_ns2mac_t : public ds3packet_t {
public:
#if CCFDEBUG
    virtual void dump (void);
#endif
    virtual ~ds3packet_ns2mac_t() { std::cout << "Destroy " << __func__ << std::endl;}

    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (ds3_packet_buffer_t *peer, size_t pos_peer);

    virtual int set_content (ds3_packet_buffer_t *peer)
        { if (0 > ds3packet_t::set_content(peer)) { return -1; } this->get_header(); return 0; }

    virtual ds3_packet_buffer_t * insert_to (size_t pos_peer, ds3_packet_buffer_t *peer, size_t begin_self, size_t end_self);

    //int set_header (ds3hdr_mac_t * mhdr) { if (NULL == mhdr) {return -1;} memmove (&(this->machdr), mhdr, sizeof (*mhdr)); return 0; } /**< set the NS2 packet header */
    //ds3hdr_mac_t & get_header (void) { this->machdr.length = this->get_content_ref().size(); return machdr; } /**< get a reference of the MAC header */

    bool operator == (const ds3packet_nbsmac_t & rhs); /**< check if two ns2 packets are identical */
    bool operator != (const ds3packet_nbsmac_t & rhs) { return ! (*this == rhs); } /**< check if two ns2 packets are not identical */

private:
    //ssize_t hdr_to_nbs (uint8_t *nbsbuf, size_t szbuf) { this->get_header(); return ds3hdr_mac_to_nbs (nbsbuf, szbuf, &(this->machdr)); }
    //ds3hdr_mac_t machdr; /**< the MAC packet header */
};

/** @brief the ccf pack class for NS2 */
class ds3_ccf_pack_ns2_t : public ds3_ccf_pack_t {
public:
protected:
    virtual void recycle_packet (ds3packet_t *p) { my_recycle_packet (p); }
    virtual void drop_packet (ds3packet_t *p) { my_drop_packet (p); }
    virtual int start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id);
    virtual double current_time (void) { return my_time(); }
};

/** @brief the ccf unpack class for NS2 */
class ds3_ccf_unpack_ns2_t : public ds3_ccf_unpack_t {
public:
protected:
    virtual void recycle_packet (ds3packet_t *p) { std::cout << "Recycle CCF segment: " << std::endl; p->dump(); /** we don't need to reenter again, since the CCF is already in global queue: my_recycle_packet (p);*/ }
    virtual void drop_packet (ds3packet_t *p) { std::cout << "Warning: CCF segment unprocessed/corrupted: " << std::endl; p->dump(); /*my_drop_packet (p);*/ }
    virtual int signify_packet (ds3_packet_buffer_t & macbuffer);
    virtual int signify_piggyback (int sc, size_t request);
};

#endif /* _NS2CCF_H */

