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

    virtual uint8_t & at(size_t i);
    virtual ssize_t block_size_at (size_t pos);
    DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS(ds3_packet_buffer_gpkt_t);
};

inline ds3_packet_buffer_gpkt_t::~ds3_packet_buffer_gpkt_t() {}

/** @brief packet class for generic Packet */
class ds3packet_gpkt_t : public ds3packet_t {
public:
#if CCFDEBUG
    virtual void dump (void);
#endif
    virtual ~ds3packet_gpkt_t() { std::cout << "Destroy " << __func__ << std::endl;}
    ds3packet_gpkt_t() : pkt(0) {}

    /* OUT */
    virtual ds3_packet_buffer_t * insert_to (size_t pos_peer, ds3_packet_buffer_t *peer, size_t begin_self, size_t end_self);

    /* IN */
    void set_packet (ds3_packet_generic_t ns2pkt, size_t szpkt) { pkt = ns2pkt; sz = szpkt; }

    //int set_header (ds3hdr_mac_t * mhdr) { if (NULL == mhdr) {return -1;} memmove (&(this->machdr), mhdr, sizeof (*mhdr)); return 0; } /**< set the NS2 packet header */
    //ds3hdr_mac_t & get_header (void) { this->machdr.length = this->get_content_ref().size(); return machdr; } /**< get a reference of the MAC header */

    //bool operator == (const ds3packet_nbsmac_t & rhs); /**< check if two ns2 packets are identical */
    //bool operator != (const ds3packet_nbsmac_t & rhs) { return ! (*this == rhs); } /**< check if two ns2 packets are not identical */
#if CCFDEBUG
    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (ds3_packet_buffer_t *peer, size_t pos_peer);
#endif

private:
    ds3_packet_generic_t pkt; // a generic pointer for packet
    size_t sz; // the size of packet
};

/** @brief the ccf pack class for NS2 */
class ds3_ccf_pack_ns2_t : public ds3_ccf_pack_t {
public:
protected:
    virtual void recycle_packet (ds3packet_t *p);
    virtual void drop_packet (ds3packet_t *p);
    virtual int start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id);
    virtual double current_time (void);
};

/** @brief the ccf unpack class for NS2 */
class ds3_ccf_unpack_ns2_t : public ds3_ccf_unpack_t {
public:
protected:
    virtual void recycle_packet (ds3packet_t *p);
    virtual void drop_packet (ds3packet_t *p);
    virtual int signify_packet (ds3_packet_buffer_t & macbuffer);
    virtual int signify_piggyback (int sc, size_t request);
};

inline double
ds3_ccf_pack_ns2_t::current_time (void)
{
    return time(NULL); //return Scheduler::instance().clock();
}

inline void
ds3_ccf_pack_ns2_t::recycle_packet (ds3packet_t *p)
{
    ds3packet_ccf_t *pc = dynamic_cast<ds3packet_ccf_t *>(p);
    assert (NULL == pc); // it should NOT be ds3packet_ccf_t
    ds3packet_gpkt_t *pn = dynamic_cast<ds3packet_gpkt_t *>(p);
    assert (NULL != pn); // it should be ds3packet_gpkt_t
    delete p;
}

inline void
ds3_ccf_pack_ns2_t::drop_packet (ds3packet_t *p)
{
    // fatal error!
    assert (0);
    this->recycle_packet (p);
}

inline void
ds3_ccf_unpack_ns2_t::recycle_packet (ds3packet_t *p)
{
    ds3packet_ccf_t *pc = dynamic_cast<ds3packet_ccf_t *>(p);
    assert (NULL != pc); // it should be ds3packet_ccf_t
    ds3packet_gpkt_t *pn = dynamic_cast<ds3packet_gpkt_t *>(p);
    assert (NULL == pn); // it should NOT be ds3packet_gpkt_t
    delete p;
}

inline void
ds3_ccf_unpack_ns2_t::drop_packet (ds3packet_t *p)
{
    // fatal error!
    assert (0);
    this->recycle_packet (p);
}


#if CCFDEBUG

#else
#include <packet.h> // NS2

size_t ns2pkt_get_size (Packet *p);

/**
 * @brief the packet content class for NS2 Packet class
 */
class ds3_packet_buffer_ns2_t : public ds3_packet_buffer_gpkt_t {
public::
#if CCFDEBUG
    virtual void dump (void);
#endif
    Packet * extract_ns2pkt (size_t pos); // extract a Packet at the position pos,

    ds3_packet_buffer_ns2_t() {}
    virtual ssize_t block_size_at (size_t pos);
    DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS_MINI(ds3_packet_buffer_ns2_t);
};

inline ds3_packet_buffer_ns2_t::ds3_packet_buffer_ns2_t(ds3_packet_buffer_t *peer, size_t begin, size_t end)
    : ds3_packet_buffer_gpkt_t (peer, begin, end) { }

inline ds3_packet_buffer_ns2_t::~ds3_packet_buffer_ns2_t() {}

/** @brief packet class for NS2 Packet */
class ds3packet_ns2mac_t : public ds3packet_gpkt_t {
public:
#if CCFDEBUG
    virtual void dump (void);
#endif
    void set_ns2packet (Packet *pkt1) { size_t sz = ns2pkt_get_size(pkt1); set_packet((ds3_packet_generic_t)pkt1, sz); }
};

#endif

#if CCFDEBUG
int test_ns2ccf (void);
#endif

#endif /* _NS2CCF_H */
