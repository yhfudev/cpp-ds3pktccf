/**
 * @file    ds3ccfns2.h
 * @brief   CCF class for NS2 DOCSIS module
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-19
 * @copyright Yunhui Fu (2014)
 */

#ifndef _DS3CCFNS2_H
#define _DS3CCFNS2_H

#include "ds3pktgnc.h"

#ifndef USE_DS3NS2
#define USE_DS3NS2 1
#endif

#if USE_DS3NS2

#include <packet.h> // NS2
#include "mac-docsis.h" // NS2

// Packet
struct hdr_docsisccf {
    ds3hdr_ccf_t ccfhdr;

    static int offset_;
    static int & offset() { return offset_; }
    static hdr_docsisccf * access(const Packet* p) { return (hdr_docsisccf*) p->access(offset_); }
};
#define HDR_DOCSISCCF(p)   (hdr_docsisccf::access(p))


/** @brief the ccf pack class for NS2 */
class ds3_ccf_pack_ns2_t : public ds3_ccf_pack_t {
public:
    ds3_ccf_pack_ns2_t(MacDocsisCM * cm1 = NULL, size_t pbmul = 0) : ds3_ccf_pack_t(pbmul), cm(cm1) {}
    int process_packet (unsigned char tbindex, Packet *p);

protected:
    virtual void recycle_packet (ds3packet_t *p);
    virtual void drop_packet (ds3packet_t *p);
    virtual int start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id);
    virtual double current_time (void);

private:
    size_t get_ns2_piggyback (unsigned char tbindex);
    bool get_ns2_grant (unsigned char tbindex, int grant_type, ds3_grant_t & grant);
    void add_more_grants (unsigned char tbindex);

    MacDocsisCM *cm;
};

/** @brief the ccf unpack class for NS2 */
class ds3_ccf_unpack_ns2_t : public ds3_ccf_unpack_t {
public:
    ds3_ccf_unpack_ns2_t(MacDocsisCMTS * cmts1 = NULL, size_t pbmul = 0) : ds3_ccf_unpack_t(pbmul), cmts(cmts1) {}
    int process_packet (Packet *p);

protected:
    virtual void recycle_packet (ds3packet_t *p);
    virtual void drop_packet (ds3packet_t *p);
    virtual int signify_packet (ds3_packet_buffer_t & macbuffer);
    virtual int signify_piggyback (int sc, size_t request);

private:
    MacDocsisCMTS *cmts;
};

inline double
ds3_ccf_pack_ns2_t::current_time (void)
{
    return Scheduler::instance().clock();
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

size_t ns2pkt_get_size (Packet *p);

/**
 * @brief the packet content class for NS2 Packet class
 */
class ds3_packet_buffer_ns2_t : public ds3_packet_buffer_gpkt_t {
public:
#if CCFDEBUG
    virtual void dump (void);
#endif
    Packet * extract_ns2pkt (size_t pos);

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


#if CCFDEBUG
int test_ns2ccf (void);
#endif

#endif

#endif /* _DS3CCFNS2_H */
