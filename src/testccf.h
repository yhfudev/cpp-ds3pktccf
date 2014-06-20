/**
 * @file    testccf.h
 * @brief   test cases for CCF
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-19
 * @copyright Yunhui Fu (2014)
 */
#ifndef _TESTCCF_H
#define _TESTCCF_H

#include "ds3pktccf.h"

void my_recycle_packet (ds3packet_t *p);
void my_drop_packet (ds3packet_t *p);
double my_time(void);

/** @brief packet for NS2 */
class ds3packet_ns2_t : public ds3packet_t {
public:
    virtual ~ds3packet_ns2_t() { std::cout << "Destroy " << __func__ << std::endl;}

    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t hdr_to_nbs (uint8_t *nbsbuf, size_t szbuf) { machdr.length = this->get_content_ref().size(); return ds3hdr_mac_to_nbs (nbsbuf, szbuf, &(this->machdr)); }

    virtual int set_content (uint8_t *nbsbuf, size_t szbuf) { if (ds3packet_t::set_content(nbsbuf, szbuf) >= 0) { machdr.length = szbuf; return 0; } return -1; }
    virtual int set_content (std::vector<uint8_t> & newbuf) { if (ds3packet_t::set_content(newbuf) >= 0) { machdr.length = newbuf.size(); return 0; } return -1; }
    virtual int set_content (std::vector<uint8_t>::iterator & begin1, std::vector<uint8_t>::iterator & end1)
         { if (ds3packet_t::set_content(begin1, end1) >= 0) { machdr.length = (end1 - begin1); return 0; } return -1; }

    virtual void dump (void);

    int set_header (ds3hdr_mac_t * mhdr) { if (NULL == mhdr) {return -1;} memmove (&(this->machdr), mhdr, sizeof (*mhdr)); return 0; } /**< set the NS2 packet header */
    ds3hdr_mac_t & get_header (void) { return machdr; } /**< get a reference of the MAC header */

    bool operator == (const ds3packet_ns2_t & rhs); /**< check if two ns2 packets are identical */
    bool operator != (const ds3packet_ns2_t & rhs) { return ! (*this == rhs); } /**< check if two ns2 packets are not identical */

private:
    ds3hdr_mac_t machdr; /**< the MAC packet header */
};

/** @brief the ccf pack class for NS2 */
class ds3ns2_ccf_pack_t : public ds3_ccf_pack_t {
public:
protected:
    virtual void recycle_packet (ds3packet_t *p) { my_recycle_packet (p); }
    virtual void drop_packet (ds3packet_t *p) { my_drop_packet (p); }
    virtual int start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id);
    virtual double current_time (void) { return my_time(); }
};

/** @brief the ccf unpack class for NS2 */
class ds3ns2_ccf_unpack_t : public ds3_ccf_unpack_t {
public:
protected:
    virtual void recycle_packet (ds3packet_t *p) { std::cout << "Recycle CCF segment: " << std::endl; p->dump(); /** we don't need to reenter again, since the CCF is already in global queue: my_recycle_packet (p);*/ }
    virtual void drop_packet (ds3packet_t *p) { std::cout << "Warning: CCF segment unprocessed/corrupted: " << std::endl; p->dump(); /*my_drop_packet (p);*/ }
    virtual int signify_packet (std::vector<uint8_t> & macbuffer);
    virtual int signify_piggyback (int sc, size_t request);
};

#if TESTCCF
int test_ccfhdr (void);
int test_machdr (void);
int test_pack (void);
int test_pktclass (void);
#endif

#endif /* _TESTCCF_H */
