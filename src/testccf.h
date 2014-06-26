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
#include "testmac.h"

void my_recycle_packet (ds3packet_t *p);
void my_drop_packet (ds3packet_t *p);
double my_time(void);

/** @brief the ccf pack class for nbs */
class ds3_ccf_pack_nbs_t : public ds3_ccf_pack_t {
public:
protected:
    virtual void recycle_packet (ds3packet_t *p) { my_recycle_packet (p); }
    virtual void drop_packet (ds3packet_t *p) { my_drop_packet (p); }
    virtual int start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id);
    virtual double current_time (void) { return my_time(); }
};

/** @brief the ccf unpack class for nbs */
class ds3_ccf_unpack_nbs_t : public ds3_ccf_unpack_t {
public:
protected:
    virtual void recycle_packet (ds3packet_t *p) { std::cout << "Recycle CCF segment: " << std::endl; p->dump(); /** we don't need to reenter again, since the CCF is already in global queue: my_recycle_packet (p);*/ }
    virtual void drop_packet (ds3packet_t *p) { std::cout << "Warning: CCF segment unprocessed/corrupted: " << std::endl; p->dump(); /*my_drop_packet (p);*/ }
    virtual int signify_packet (ds3_packet_buffer_t & macbuffer);
    virtual int signify_piggyback (int sc, size_t request);
};

#if CCFDEBUG
int test_pack (void);
int test_pktclass (void);
#endif

#endif /* _TESTCCF_H */
