/**
 * @file    ds3pktgnc.h
 * @brief   genetic packet pointer for ds3packet
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-30
 * @copyright Yunhui Fu (2014)
 */

#ifndef _DS3PKTGNC_H
#define _DS3PKTGNC_H

#include "ds3pktccf.h"

/* To support generic packet type (which's desclared as void * here),
 * we use a extract_xx() function to extract the packet in the buffer,
 * the function ``loose'' checks only if the start position is 0,
 * the further checks, such as the actual size of the packet vs the size stored in
 * the buffer, will be checked in a derived class.
 *
 * That also influence the interface setup generic packet(set_packet) in class ds3packet_gpkt_t
 * which requires the size of packet as a input argument for the function to avoid the size() interface for the packet.
 */

#define ds3_packet_generic_t void *

typedef struct _ds3pktbufns2_info_t {
    ds3_packet_generic_t pkt; /**< the Packet */
    size_t pos;  /**< data start at pos in pkt */
    size_t sz;   /**< data size */
#if CCFDEBUG
    bool flg_extracted; /**< if the packet was extracted; if so, there's may have risk to extract it again, because we just store the pointer to a Packet and the previous useer may free it before another extract() */
#endif
} ds3pktbufns2_info_t;

/**
 * @brief the packet content class for generic Packet class
 */
class ds3_packet_buffer_gpkt_t : public ds3_packet_buffer_t {
private:
    size_t szpkt;
    std::vector<ds3pktbufns2_info_t> pktlist; /**< the packet list of content */
    bool insert_gpkt_idx (size_t i, size_t szcur, size_t pos_self, ds3_packet_generic_t pkt, size_t begin_peer, size_t end_peer);
protected:
    bool get_gpkt_info (size_t pos /* IN */, ds3_packet_generic_t &ret_pkt /* OUT */, size_t & ret_begin /* OUT */, size_t & ret_end /* OUT */); /**< get the packet info at the position pos */

public:
#if CCFDEBUG
    virtual void dump (void);
#endif
    ds3_packet_buffer_gpkt_t() : szpkt(0) {}

    /* IN */
    bool insert_gpkt (size_t pos_self, ds3_packet_generic_t peer_pkt, size_t begin_peer, size_t end_peer);
    /* OUT */
    ds3_packet_generic_t extract_gpkt (size_t pos); // extract a Packet at the position pos,
    bool erase (size_t begin_self, size_t end_self); /**< erase the content */
    ds3_packet_buffer_t * insert_to_base (size_t pos_peer, ds3_packet_buffer_gpkt_t *peer, size_t begin_self, size_t end_self); /**< generic insert_to function for gpkt and its child class */
    ds3_packet_buffer_t * copy_to_base (size_t pos_peer, ds3_packet_buffer_gpkt_t * peer, size_t begin_self, size_t end_self); /**< generic copy_to function for gpkt and its child class */

    virtual uint8_t & at(size_t i);
    virtual ssize_t block_size_at (size_t pos);
    DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS(ds3_packet_buffer_gpkt_t);
};

#define DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS_GPKT(ds3_real_type) \
  public: \
    virtual ssize_t copy (size_t pos_self, ds3_packet_buffer_t *arg_peer, size_t begin_peer, size_t end_peer) { \
        DS3_PKTCNT_IMPLEMENT_CHILD_COPY(ds3_real_type, pos_self, arg_peer, begin_peer, end_peer); \
    } \
    virtual ssize_t insert (size_t pos_self, ds3_packet_buffer_t *arg_peer, size_t begin_peer, size_t end_peer) { \
        DS3_PKTCNT_IMPLEMENT_CHILD_INSERT(ds3_real_type, pos_self, arg_peer, begin_peer, end_peer); \
    } \
  protected: \
    virtual ds3_packet_buffer_t * insert_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self) \
    { \
        DS3_DYNCST_CHKRET_CONTENT_POINTER(ds3_real_type, arg_peer); \
        assert (NULL != peer); \
        if (peer == this->insert_to_base (pos_peer, peer, begin_self, end_self)) { \
            return arg_peer; \
        } \
        return NULL; \
    } \
    virtual ds3_packet_buffer_t * copy_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self) \
    { \
        DS3_DYNCST_CHKRET_CONTENT_POINTER(ds3_real_type, arg_peer); \
        assert (NULL != peer); \
        if (peer == this->copy_to_base (pos_peer, peer, begin_self, end_self)) { \
            return arg_peer; \
        } \
        return NULL; \
    } \
    DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS_MINI(ds3_real_type)

inline ds3_packet_buffer_gpkt_t::~ds3_packet_buffer_gpkt_t() {}

#define DS3_PKT_DECLARE_MEMBER_FUNCTIONS_GPKT(ds3_real_type) \
virtual ds3_packet_buffer_t * insert_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self) { \
    DS3_DYNCST_CHKRET_DS3PKT_BUFFER(ds3_real_type, arg_peer); \
    assert (NULL != peer); \
    if (begin_self >= end_self) { \
        return arg_peer; \
    } \
    if (false == peer->insert_gpkt (pos_peer, this->pkt, begin_self, end_self)) { \
        if (flg_peer_is_new) { free (peer); } \
        return NULL; \
    } \
    return arg_peer; \
}

/** @brief packet class for generic Packet */
class ds3packet_gpkt_t : public ds3packet_t {
public:
#if CCFDEBUG
    virtual void dump (void);
#endif
    virtual ~ds3packet_gpkt_t() { std::cout << "Destroy " << __func__ << std::endl;}
    ds3packet_gpkt_t() : pkt(0) {}

    /* OUT */
    //virtual ds3_packet_buffer_t * insert_to (size_t pos_peer, ds3_packet_buffer_t *peer, size_t begin_self, size_t end_self);
    DS3_PKT_DECLARE_MEMBER_FUNCTIONS_GPKT (ds3_packet_buffer_gpkt_t)

    /* IN */
    void set_packet (ds3_packet_generic_t ns2pkt, size_t szpkt) { pkt = ns2pkt; sz = szpkt; }
    ds3_packet_generic_t get_packet (void) { return pkt; }

    virtual ssize_t size(void) { return this->sz; }

    //int set_header (ds3hdr_mac_t * mhdr) { if (NULL == mhdr) {return -1;} memmove (&(this->machdr), mhdr, sizeof (*mhdr)); return 0; } /**< set the NS2 packet header */
    //ds3hdr_mac_t & get_header (void) { this->machdr.length = this->get_content_ref().size(); return machdr; } /**< get a reference of the MAC header */

    //bool operator == (const ds3packet_nbsmac_t & rhs); /**< check if two ns2 packets are identical */
    //bool operator != (const ds3packet_nbsmac_t & rhs) { return ! (*this == rhs); } /**< check if two ns2 packets are not identical */
#if CCFDEBUG
    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (ds3_packet_buffer_t *peer, size_t pos_peer);
#endif

protected:
    ds3_packet_generic_t pkt; // a generic pointer for packet
    size_t sz; // the size of packet
};

#if CCFDEBUG
int test_pktgnc (void);
#endif

#endif /* _DS3PKTGNC_H */
