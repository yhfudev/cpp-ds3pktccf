/**
 * @file    testccf.cc
 * @brief   test cases for CCF
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-19
 * @copyright Yunhui Fu (2014)
 */

#include <stdio.h>

#include "ds3pktccf.h"
#include "testccf.h"

int add_channel_packet (ds3packet_t * p);

int
ds3_ccf_pack_nbs_t::start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id)
{
    std::cout << "Got a packed CCF segment: " << std::endl;
    std::cout << "  -- start timer: tm=" << abs_time << ", event=" << ds3_event2desc(evt) << ", pkt.size=" << p->get_size() << ", channelId=" << channel_id << std::endl;
    add_channel_packet (p);
    return 0;
}

int
ds3_ccf_unpack_nbs_t::signify_piggyback (int sc, size_t request)
{
    std::cout << "Got a unpacked piggyback request: sc=" << sc << ", request=" << request << std::endl;
    // append the assemblied packet, we'll delete tht packet later
    return 0;
}

int
ds3_ccf_unpack_nbs_t::signify_packet (ds3_packet_buffer_t & macbuffer)
{
    assert (macbuffer.size() > 0);
    // append the assemblied packet, we'll delete tht packet later
    ds3packet_nbsmac_t *p = new ds3packet_nbsmac_t();
    assert (NULL != p);
    p->from_nbs (&macbuffer, 0);
    std::cout << "Got a unpacked MAC packet:" << std::endl;
    add_channel_packet (p);
    return 0;
}

/*****************************************************************************/
#if 1 // CCFDEBUG
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

void
shuffer_channel_packets (void)
{
    int i;
    int nlast = g_pkt_in_channel.size();
    ds3packet_t * pkt;
    for (i = 0; i < nlast; i ++) {
        int rand1 = rand() % nlast;
        int rand2 = rand() % nlast;
        if (rand1 == rand2) {
            continue;
        }
        pkt = g_pkt_in_channel[rand1];
        g_pkt_in_channel[rand1] = g_pkt_in_channel[rand2];
        g_pkt_in_channel[rand2] = pkt;
    }
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

void
clean_all_packets (void)
{
    ds3packet_t *pkt = NULL;
    size_t i, j;
    j = 0;
    for (i = get_channel_packet_length(); i > 0; i --, j ++) {
        pkt = get_channel_packet(j);
        set_channel_packet (j, NULL);
        if (NULL != pkt) {
            delete pkt;
        }
    }
    j = 0;
    for (i = g_pkt_in_recycle.size(); i > 0; i --, j ++) {
        pkt = g_pkt_in_recycle.at(j);
        //g_pkt_in_recycle.at(j) = NULL;
        if (NULL != pkt) {
            delete pkt;
        }
    }
    g_pkt_in_recycle.erase(g_pkt_in_recycle.begin(), g_pkt_in_recycle.end());
    g_pkt_in_channel.erase(g_pkt_in_channel.begin(), g_pkt_in_channel.end());
}

#ifndef REQUIRE
#define REQUIRE assert
#endif

//#define NUM_PKT 5

/**
 * @brief test pack/unpack
 */
int
test_pack_gp (size_t * grantsize, size_t numg, size_t * packetsize, size_t nump)
{
    int ret = 0;
    size_t i = 0;
    int j = 0;
    double next_gt_time = 0.0;
    ds3_ccf_pack_nbs_t pak;
    ds3_ccf_unpack_nbs_t unpak;
    std::vector<ds3_grant_t> mygrants;
    ds3_grant_t gt;
    ds3packet_nbsmac_t * pktns2 = NULL;
    ds3packet_t *pkt = NULL;

    std::vector<size_t> size_pkt; // the size of each packet
    std::vector<size_t> size_grant; // the granted size
    size_t szpkt;
    size_t sztotal = 0; // the total size of packets
    size_t szcur = 0;

    if (NULL == packetsize) {
        for (i = 0; i < nump; i ++) {
            szpkt = rand() % (nump * 2) + 1;
            size_pkt.push_back (szpkt);
            sztotal += szpkt + ds3hdr_mac_to_nbs (NULL, 0, NULL);
        }
    } else {
        for (i = 0; i < nump; i ++) {
            szpkt = packetsize[i];
            size_pkt.push_back (szpkt);
            sztotal += szpkt + ds3hdr_mac_to_nbs (NULL, 0, NULL);
        }
    }
    if (NULL == grantsize) {
        for (i = 0; sztotal > szcur; i ++) {
            szpkt = rand() % (nump * 5);
            assert (szpkt >= 0);
            size_grant.push_back (szpkt + ds3hdr_ccf_to_nbs (NULL, 0, NULL)); // the ccf header size
            szcur += szpkt;
        }
    } else {
        for (i = 0; sztotal > szcur; i ++) {
            if (i < numg) {
                szpkt = grantsize[i];
            } else {
                szpkt = rand() % (nump * 5);
            }
            assert (szpkt >= 0);
            size_grant.push_back (szpkt + ds3hdr_ccf_to_nbs (NULL, 0, NULL)); // the ccf header size
            szcur += szpkt;
        }
    }

    size_t max_pkt = 0;
    std::cout << "The configured size:" << std::endl;
    std::cout << "size_t size_pkt[] = {" << std::endl << "  ";
    for (i = 0; i < size_pkt.size(); i ++) {
        if (max_pkt < size_pkt[i]) { max_pkt = size_pkt[i]; }
        std::cout << size_pkt[i] << ", ";
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl << "  ";
        }
    }
    std::cout << std::endl << "};" << std::endl;

    std::cout << "size_t grantsize[] = {" << std::endl << "  ";
    for (i = 0; i < size_grant.size(); i ++) {
        std::cout << size_grant[i] << ", ";
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl << "  ";
        }
    }
    std::cout << std::endl << "};" << std::endl;

    std::vector<uint8_t> pktcontent;
    //memset (pktcontent, 0xC0, sizeof(pktcontent) - 1);
    for (i = 0; i < max_pkt + 1; i ++) {
        pktcontent.push_back( 0x11 + i);
    }

    next_gt_time = 0.0;
    my_set_time (next_gt_time);

    pak.set_pbmultiplier(5);
    unpak.set_pbmultiplier(5);
    REQUIRE (5 == pak.get_pbmultiplier());
    REQUIRE (5 == unpak.get_pbmultiplier());

    next_gt_time = 1.0;
    for (i = 0; i < size_grant.size(); i ++) {
        assert (size_grant.at(i) >= (size_t)    ds3hdr_ccf_to_nbs (NULL, 0, NULL));
        gt.set_size(size_grant.at(i)); // CCF header(8) + data(7)
        gt.set_channel_id(1);
        gt.set_time(next_gt_time);
        mygrants.push_back (gt);
    }

    for (i = 0; i < mygrants.size(); i ++) {
        std::cout << "grant[" << i << "]: g.size=" << mygrants[i].get_size() << ", g.cid=" << mygrants[i].get_channel_id() << ", g.time=" << mygrants[i].get_time() << std::endl;
    }

    // we add 5 packet (size=5)
    ds3_packet_buffer_nbs_t nbscnt;
    for (i = 0; i < nump; i ++) {
        pktns2 = new ds3packet_nbsmac_t ();
        assert (NULL != pktns2);

        // set the content first
        std::vector<uint8_t>::iterator itb = pktcontent.begin();
        std::vector<uint8_t>::iterator ite = pktcontent.begin() + size_pkt.at(i);
        nbscnt.append(itb, ite);
        pktns2->set_content (&nbscnt);

        pktns2->get_header().sequence = i;
        pak.process_packet(pktns2);
        //std::cout << "channel packet # = " << get_channel_packet_length() << std::endl;
        nbscnt.resize(0);
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
    //REQUIRE ( 3 == get_channel_packet_length() );
    size_t nlast = get_channel_packet_length();

    // randomize the packets in the channel
    shuffer_channel_packets ();

    std::cout << "AFTER shuffer, channel packet # = " << get_channel_packet_length() << std::endl;
    for (i = 0; i < (size_t)get_channel_packet_length(); i ++) {
        pkt = get_channel_packet(i);
        if (NULL == pkt) {
            std::cout << "channel pkt NULL" << std::endl;
        } else {
            pkt->dump();
        }
    }

    next_gt_time = 1.0;
    my_set_time (next_gt_time);

    // ``transfer the segments
    // since we append the new assemblied packet to the same global vector,
    // so we need to get the original length of the queue.
    j = 0;
    for (i = get_channel_packet_length(); i > 0; i --, j ++) {
        pkt = get_channel_packet(j);
        unpak.process_packet (pkt);
        //set_channel_packet (j, NULL); // because the CCF packet were deleted by the process_packet()
    }
    std::cout << "channel packet # = " << get_channel_packet_length() << std::endl;

    ds3packet_nbsmac_t * pktns1 = NULL;
    for (i = 0; i < nump; i ++) {
        // compare the packet
        pktns1 = dynamic_cast<ds3packet_nbsmac_t *>(get_channel_packet(nlast + i));
        REQUIRE (NULL != pktns1);
        assert (pktns1->get_header().sequence < nump);
        pktns2 = dynamic_cast<ds3packet_nbsmac_t *>(g_pkt_in_recycle[pktns1->get_header().sequence]);
        REQUIRE (NULL != pktns2);
        if (*pktns1 != *pktns2) {
            std::cout << "packet(" << i << ") not equal! sequence=" << pktns1->get_header().sequence << std::endl;
            ret = -1;
        }
    }

    REQUIRE ( nlast + nump == (size_t)get_channel_packet_length() );
    assert (g_pkt_in_recycle.size() == nump);

    clean_all_packets ();
    return ret;
}

#define NUMARRAY(v) (sizeof(v)/sizeof(v[0]))


int
test_pack_fix1 (void)
{

    size_t size_pkt[] = {
        44, 47, 58, 56, 54, 56, 47, 13, 10, 2, 3, 8, 51, 20, 24, 47,
        1, 7, 53, 17, 12, 9, 28, 10, 3, 51, 3, 44, 8, 56
    };

    size_t grantsize[] = {
        37, 110, 230, 266, 277, 275
    };

    return test_pack_gp(grantsize, NUMARRAY(grantsize), NULL, NUMARRAY(size_pkt));
}

int
test_pack_fix2 (void)
{
    size_t size_pkt[] = {
        63, 100, 92, 67, 95, 5, 37, 43, 52, 145, 70, 117, 4, 6, 5, 24,
        120, 25, 17, 1, 37, 142, 122, 37, 108, 35, 69, 99, 115, 125, 27, 42,
        73, 134, 108, 31, 3, 144, 73, 54, 1, 6, 18, 4, 12, 38, 28, 147,
        62, 44, 147, 99, 49, 117, 151, 21, 15, 83, 119, 129, 72, 9, 18, 144,
        143, 142, 38, 145, 133, 110, 62, 133, 132, 79, 1, 143,
    };
    size_t grantsize[] = {
        47, 111, 8, 353, 322, 247, 11, 67, 151, 253, 179, 165, 108, 237, 141, 255,
        322, 251, 110, 252, 332, 147, 108, 236, 348, 245, 233, 99, 111, 309, 181, 242,
    };

    return test_pack_gp(grantsize, NUMARRAY(grantsize), NULL, NUMARRAY(size_pkt));
}

int
test_pack_random (void)
{
    srand(time(NULL));
    size_t nump = rand () % 100;
    if (nump < 2) {nump = 2;}
    size_t numg = rand () % (nump / 2);
    return test_pack_gp(0, numg, NULL, nump);
}

int
test_pack (void)
{
    REQUIRE (0 == test_pack_fix1());
    REQUIRE (0 == test_pack_fix2());
    REQUIRE (0 == test_pack_random());
    return test_pack_random();
}

/*****************************************************************************/
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

#if TESTCCF
int
main1(void)
{
    test_pktclass ();
    test_machdr();
    test_ccfhdr();
    test_pktcnt ();
    test_pack();
    return 0;
}
#endif

#endif
