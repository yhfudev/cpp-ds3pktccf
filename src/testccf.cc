/**
 * @file    testccf.cc
 * @brief   test cases for CCF
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-19
 * @copyright Yunhui Fu (2014)
 */

#include <stdio.h>

#include "testccf.h"

int add_channel_packet (ds3packet_t * p);

ssize_t
ds3packet_ns2_t::to_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    ssize_t szret = 0;
    size_t szcur = 0;

    if (0 == szbuf) {
        return ds3hdr_mac_to_nbs (NULL, 0, &(this->machdr)) + this->buffer.size();
    }
    szret = ds3hdr_mac_to_nbs (nbsbuf, szbuf, &(this->machdr));
    if (szret < 0) {
        return -1;
    }
    if (szret + this->buffer.size() > szbuf) {
        return -1;
    }
    szcur += szret;

    std::copy (this->buffer.begin(), this->buffer.end(), nbsbuf + szcur);

    return szcur;
}

ssize_t
ds3packet_ns2_t::from_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    ssize_t szret = 0;
    size_t szcur = 0;
    if (0 == szbuf) {
        return ds3hdr_mac_from_nbs (NULL, 0, &(this->machdr));
    }
    // the ``MAC header''
    ds3hdr_mac_t tmphdr;
    szret = ds3hdr_mac_from_nbs (nbsbuf, szbuf, &tmphdr);
    if (szret < 0) {
        return -1;
    }
    szcur += szret;
    if (szcur + tmphdr.length > szbuf) {
        return -1;
    }
    memmove (&(this->machdr), &tmphdr, sizeof (tmphdr));
    // the content
#if 1
    buffer.resize(tmphdr.length);
    std::copy (nbsbuf + szcur, nbsbuf + szcur + tmphdr.length, this->buffer.begin());
#else
    this->buffer.resize(0);
    this->buffer.insert (this->buffer.begin(), nbsbuf + szcur, nbsbuf + szcur + tmphdr.length);
#endif
    szcur += tmphdr.length;
    return szcur;
}

int
ds3ns2_ccf_unpack_t::signify_piggyback (int sc, size_t request)
{
    std::cout << "Got a unpacked piggyback request: sc=" << sc << ", request=" << request << std::endl;
    // append the assemblied packet, we'll delete tht packet later
    return 0;
}

int
ds3ns2_ccf_unpack_t::signify_packet (std::vector<uint8_t> & macbuffer)
{
    assert (macbuffer.size() > 0);
    // append the assemblied packet, we'll delete tht packet later
    ds3packet_ns2_t *p = new ds3packet_ns2_t();
    assert (NULL != p);
    p->from_nbs (&macbuffer[0], macbuffer.size());
    std::cout << "Got a unpacked MAC packet:" << std::endl;
    add_channel_packet (p);
    return 0;
}

int
ds3ns2_ccf_pack_t::start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id)
{
    std::cout << "Got a packed CCF segment: " << std::endl;
    std::cout << "  -- start timer: tm=" << abs_time << ", event=" << evt << ", pkt.size=" << p->get_size() << ", channelId=" << channel_id << std::endl;
    add_channel_packet (p);
    return 0;
}

//bool operator < (const ds3packet_ns2_t & lhs, const ds3packet_ns2_t & rhs);
bool
ds3packet_ns2_t::operator == (const ds3packet_ns2_t & rhs)
{
    if (this->machdr.length != rhs.machdr.length) {
        return false;
    }
    if (this->machdr.sequence != rhs.machdr.sequence) {
        return false;
    }
    if (this->buffer.size() != rhs.buffer.size()) {
        return false;
    }
    for (size_t i = 0; i < this->buffer.size(); i ++) {
        if (this->buffer[i] != rhs.buffer[i]) {
            return false;
        }
    }
    return true;
}

void
ds3packet_ns2_t::dump (void)
{
    ds3hdr_mac_t & machdr = this->get_header();
    std::cout << "MAC pkt"
        //<< ", type: " << typeid(p).name()
        << ", hdr.sequence=" << machdr.sequence
        << ", cnt.sz="      << this->get_content_ref().size() << "/" << this->get_size()
        << ", hdr.length="  << machdr.length
        << std::endl;
    this->dump_content ();
}

#if 0
void
ds3_dump_packet (ds3packet_t *p)
{
    bool flg_proc = false;
    ds3packet_ns2_t *pktns2 = NULL;
    ds3packet_ccf_t *pktccf = NULL;

    pktns2 = dynamic_cast<ds3packet_ns2_t *>(p);
    if (pktns2) {
        ds3hdr_mac_t & machdr = pktns2->get_header();
        std::cout << "MAC pkt"
            //<< ", type: " << typeid(p).name()
            << ", hdr.sequence=" << machdr.sequence
            << ", cnt.sz="      << p->get_content_ref().size() << "/" << p->get_size()
            << ", hdr.length="  << machdr.length
            << std::endl;
        flg_proc = true;
    } else {
        pktccf = dynamic_cast<ds3packet_ccf_t *>(p);
    }

    if (pktccf) {
        ds3hdr_ccf_t & ccfhdr = pktccf->get_header();
        std::cout << "CCF pkt"
            //<< ", type: "       << typeid(p).name()
            << ", hdr.sequence=" << ccfhdr.sequence
            << ", cnt.sz="      << p->get_content_ref().size() << "/" << p->get_size()
            << ", hdr.pfi="     << ccfhdr.pfi
            << ", hdr.offmac="  << ccfhdr.offmac
            << ", hdr.sc="      << ccfhdr.sc
            << ", hdr.request=" << ccfhdr.request
            << ", hdr.hcs="     << ccfhdr.hcs
            << std::endl;
        flg_proc = true;
    }

    if (! flg_proc) {
        // it's a generic ds3packet_t ?
        std::cout << "Fatal: unknown packet"
            //<< ", type: " << typeid(p).name()
            << ", cnt.sz=" << p->get_content_ref().size() << "/" << p->get_size() << std::endl;
    }
    std::cout << "   content: " ;// << std::endl;
    std::vector<uint8_t>::iterator itb = p->get_content_ref().begin();
    std::vector<uint8_t>::iterator ite = p->get_content_ref().end();
    for (; itb != ite; itb ++ ) {
        printf (" %02X", *itb);
    }
    std::cout << std::endl;
}
#endif

/*****************************************************************************/
#if 1 //TESTCCF
/* stub functions */

double g_my_time = 0.0;
double my_time(void) { return g_my_time; }
void my_set_time(double tt) { g_my_time = tt; }

// global list of the segments sent by the packer
// to be used by the receiver to unpack the packets
std::vector<ds3packet_t *> g_pkt_in_channel;
int
add_channel_packet (ds3packet_t * p)
{
    std::cout << "Got a ds3 packet:" << std::endl;
    p->dump();
    g_pkt_in_channel.push_back(p);
    return 0;
}

int
set_channel_packet (int idx, ds3packet_t * p)
{
    g_pkt_in_channel[idx] = p;
    return 0;
}

int
get_channel_packet_length ()
{
    return g_pkt_in_channel.size();
}

ds3packet_t *
get_channel_packet (int idx)
{
    return g_pkt_in_channel.at(idx);
}

std::vector<ds3packet_t *> g_pkt_in_recycle;
void
my_recycle_packet (ds3packet_t *p)
{
    // add the processed packet to global pool
    std::cout << "recycle a ds3 packet:" << std::endl;
    p->dump();
    g_pkt_in_recycle.push_back(p);
}

void
my_drop_packet (ds3packet_t *p)
{
    // delete un-processed packet (corruption)
    std::cout << "corrupted ds3 packet ?:" << std::endl;
    p->dump();
    delete p;
}

#ifndef REQUIRE
#define REQUIRE assert
#endif

#define NUM_PKT 5

int
test_pack (void)
{
    int ret = 0;
    size_t i = 0;
    int j = 0;
    double next_gt_time = 0.0;
    ds3ns2_ccf_pack_t pak;
    ds3ns2_ccf_unpack_t unpak;
    std::vector<ds3_grant_t> mygrants;
    ds3_grant_t gt;
    ds3packet_ns2_t * pktns2 = NULL;
    ds3packet_t *pkt = NULL;

    uint8_t pktcontent[5 + NUM_PKT + 1];
    //memset (pktcontent, 0xC0, sizeof(pktcontent) - 1);
    for (i = 0; i < sizeof(pktcontent) - 1; i ++) {
        pktcontent[i] = 0xC1 + i;
    }
    pktcontent[sizeof(pktcontent) - 1] = 0;

    next_gt_time = 0.0;
    my_set_time (next_gt_time);

    pak.set_pbmultiplier(5);
    unpak.set_pbmultiplier(5);
    REQUIRE (5 == pak.get_pbmultiplier());
    REQUIRE (5 == unpak.get_pbmultiplier());

    next_gt_time = 1.0;
    gt.set_size(8+7+2*4); // CCF header(8) + data(7) + NUM_PKT*sizeof(machdr)
    gt.set_channel_id(1);
    gt.set_time(next_gt_time);
    mygrants.push_back (gt);

    next_gt_time = 2.0;
    gt.set_size(8+11+2*4);
    gt.set_channel_id(1);
    gt.set_time(next_gt_time);
    mygrants.push_back (gt);

    next_gt_time = 3.0;
    gt.set_size(8+7+1*4);
    gt.set_channel_id(1);
    gt.set_time(next_gt_time);
    mygrants.push_back (gt);

    next_gt_time = 4.0;
    gt.set_size(8+7+1*4);
    gt.set_channel_id(1);
    gt.set_time(next_gt_time);
    mygrants.push_back (gt);
    for (i = 0; i < mygrants.size(); i ++) {
        std::cout << "grant[" << i << "]: g.size=" << mygrants[i].get_size() << ", g.cid=" << mygrants[i].get_channel_id() << ", g.time=" << mygrants[i].get_time() << std::endl;
    }

    // we add 5 packet (size=5)
    for (i = 0; i < NUM_PKT; i ++) {
        pktns2 = new ds3packet_ns2_t ();
        pktns2->get_header().sequence = i;
        assert (NULL != pktns2);
        pktns2->set_content (pktcontent, (NUM_PKT/2) + i);
        pak.process_packet(pktns2);
        //std::cout << "channel packet # = " << get_channel_packet_length() << std::endl;
    }

    pak.add_grants (mygrants, 355);
    std::cout << "channel packet # = " << get_channel_packet_length() << std::endl;
    for (i = 0; i < (size_t)get_channel_packet_length(); i ++) {
        pkt = get_channel_packet(i);
        if (NULL == pkt) {
            std::cout << "channel pkt NULL" << std::endl;
        } else {
            pkt->dump();
        }
    }
    REQUIRE ( 3 == get_channel_packet_length() );

    next_gt_time = 1.0;
    my_set_time (next_gt_time);

    // ``transfer the segments
    // since we append the new assemblied packet to the same global vector,
    // so we need to get the original length of the queue.
    j = 0;
    for (i = get_channel_packet_length(); i > 0; i --, j ++) {
        pkt = get_channel_packet(j);
        unpak.process_packet (pkt);
        set_channel_packet (j, NULL); // because the CCF packet were deleted by the process_packet()
    }
    std::cout << "channel packet # = " << get_channel_packet_length() << std::endl;
    REQUIRE ( 3 + NUM_PKT == get_channel_packet_length() );
    assert (g_pkt_in_recycle.size() == NUM_PKT);
    ds3packet_ns2_t * pktns1 = NULL;
    for (i = 0; i < NUM_PKT; i ++) {
        // compare the packet
        pktns2 = dynamic_cast<ds3packet_ns2_t *>(g_pkt_in_recycle[i]);
        REQUIRE (NULL != pktns2);
        pktns1 = dynamic_cast<ds3packet_ns2_t *>(get_channel_packet(3 + i));
        REQUIRE (NULL != pktns1);
        if (*pktns1 != *pktns2) {
            std::cout << "packet(" << i << ") not equal!" << std::endl;
            ret = -1;
        }
    }

    j = 0;
    for (i = get_channel_packet_length(); i > 0; i --, j ++) {
        pkt = get_channel_packet(j);
        set_channel_packet (j, NULL);
        if (NULL != pkt) {
            delete pkt;
        }
    }
    return ret;
}

/*****************************************************************************/
int
test_ccfhdr (void)
{
    ds3hdr_ccf_t ccfhdr, ccfhdr2, *ph;
    uint8_t buffer[16];

    ph = &ccfhdr;
    memset (ph, 0, sizeof(*ph));
    ph->pfi = 1;
    ph->offmac = 50;
    ph->sequence = 10;
    ph->sc = 2;
    ph->request = 3922;
    ph->hcs = 39283;

    ph = &ccfhdr2;
    memset (ph, 0, sizeof(*ph));

    ds3hdr_ccf_to_nbs (buffer, sizeof (buffer), &ccfhdr);
    ds3hdr_ccf_from_nbs (buffer, sizeof (buffer), &ccfhdr2);
#define MYCHK1(name1) REQUIRE (ccfhdr.name1 == ccfhdr2.name1)
    MYCHK1(pfi);
    MYCHK1(r);
    MYCHK1(offmac);
    MYCHK1(sequence);
    MYCHK1(sc);
    MYCHK1(request);
    MYCHK1(hcs);

    if (0 != memcmp (&ccfhdr, &ccfhdr2, sizeof(ccfhdr))) {
        printf ("[%s()] Error in ccfhdr2!\n", __func__);
        return -1;
    }
    printf ("[%s()] Passed !\n", __func__);
    return 0;
}

/* test sort vector */
bool myfunction (int i,int j) { return (i<j); }
int
test_vectsort (void)
{
    int myints[] = {32,71,12,45,26,80,53,33};
    std::vector<int> myvector (myints, myints + 8);
    std::sort (myvector.begin(), myvector.end(), myfunction);

    // print out content:
    std::cout << "myvector contains:";
    for (std::vector<int>::iterator it=myvector.begin(); it!=myvector.end(); ++it) {
        std::cout << ' ' << *it;
    }
    std::cout << '\n';
    return 0;
}

/* test if the class call destructor correctly */
class tstcls_t {
public:
    virtual ~tstcls_t () { std::cout << "Destroy " << __func__ << std::endl; }
    virtual void publicfunc(void) { std::cout << "Public Function tstcls_t::" << __func__ << std::endl; /* should never reach to this function, the d3packet_t should be a abstract class! */assert(0); }
};

class tstcls_1_t : public tstcls_t {
public:
    virtual ~tstcls_1_t () { std::cout << "Destroy " << __func__ << std::endl; }
    virtual void publicfunc(void) { std::cout << "Public Function tstcls_1_t::" << __func__ << std::endl; }
};

class tstcls_2_t : public tstcls_t {
public:
    virtual ~tstcls_2_t () { std::cout << "Destroy " << __func__ << std::endl; }
    virtual void publicfunc(void) { std::cout << "Public Function tstcls_2_t::" << __func__ << std::endl; }
};

int
test_pktclass (void)
{
    tstcls_t * p = NULL;
    p = new tstcls_1_t();
    p->publicfunc();
    delete p;

    p = new tstcls_2_t();
    p->publicfunc();
    delete p;

    test_vectsort();
    return 0;
}

int
main1(void)
{
    test_pktclass ();
    test_ccfhdr();
    test_pack();
    return 0;
}
#endif
