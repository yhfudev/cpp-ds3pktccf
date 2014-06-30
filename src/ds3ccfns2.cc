/**
 * @file    ds3ccfns2.cc
 * @brief   CCF class for NS2 DOCSIS module
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-19
 * @copyright Yunhui Fu (2014)
 */

#include <iostream>     // std::cout, std::endl
#include "ds3ccfns2.h"

int
ds3_ccf_pack_ns2_t::start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id)
{
    std::cout << "Got a packed CCF segment: " << std::endl;
    std::cout << "  -- start timer: tm=" << abs_time << ", event=" << ds3_event2desc(evt) << ", pkt.size=" << p->get_size() << ", channelId=" << channel_id << std::endl;
    //Packet *ns2pkt = NULL; //new Packet();
    //assert (NULL != ns2pkt);
    //ns2pkt->ccfpkt = p;
    assert (0);
    return -1;
}
int
ds3_ccf_unpack_ns2_t::signify_piggyback (int sc, size_t request)
{
    std::cout << "Got a unpacked piggyback request: sc=" << sc << ", request=" << request << std::endl;
    //Packet *ns2pkt = NULL; //new Packet();
    //assert (NULL != ns2pkt);
    assert (0);
    return -1;
}

int
ds3_ccf_unpack_ns2_t::signify_packet (ds3_packet_buffer_t & macbuffer)
{
    assert (macbuffer.size() > 0);
    ds3_packet_buffer_gpkt_t *p = dynamic_cast<ds3_packet_buffer_gpkt_t *>(macbuffer.get_buffer());
    assert (NULL != p);
    //Packet *ns2pkt = p->extract_ns2pkt(0);
    ds3_packet_generic_t ns2pkt = p->extract_gpkt(0);
    assert (NULL != ns2pkt);
    assert (0);
    return -1;
}

#if CCFDEBUG

#else
#include <packet.h> // NS2
#include "hdr-docsis.h"

#if CCFDEBUG
void
ds3_packet_buffer_ns2_t::dump (void)
{
    assert (0); // TODO
    std::cout << "   content: " ;// << std::endl;
    //std::vector<uint8_t>::iterator itb = this->buffer.begin();
    //std::vector<uint8_t>::iterator ite = this->buffer.end();
    //for (; itb != ite; itb ++ ) {
    //    printf (" %02X", *itb);
    //}
    std::cout << std::endl;
}

void
ds3packet_ns2mac_t::dump (void)
{
    this->dump_content ();
}
#endif

Packet *
ds3_packet_buffer_ns2_t::extract_ns2pkt (size_t pos)
{
    ds3_packet_generic_t gp = extract_gpkt (pos);
    if (NULL == gp) {
        return NULL;
    }
    //Packet * np = (Packet *)gp;
    Packet * np = (Packet *)(gp); //dynamic_cast<Packet *>(gp);
    assert (NULL != np);
    // check the size of packet
    ssize_t ret;
    ret = ds3_packet_buffer_gpkt_t::block_size_at (pos);
    if (ret != ns2pkt_get_size(np)) {
        // error
        assert (0);
        return NULL;
    }
    return np;
}

ssize_t
ds3_packet_buffer_ns2_t::block_size_at (size_t pos)
{
    ssize_t ret;
    ret = ds3_packet_buffer_gpkt_t::block_size_at (pos);
    if (ret < 0) {
        return -1;
    }
    // check the size of packet
    if (NULL == this->extract_ns2pkt(pos)) {
        assert (0);
        return -1;
    }
    return ret;
}

size_t
ns2pkt_get_size (Packet *p)
{
    assert (NULL != p);
    struct hdr_docsis* dh = HDR_DOCSIS(p);
    //len = dh->dshdr().len;
    assert (0);
    return dh->dshdr().len;
}
#endif

#if CCFDEBUG
int
test_ns2ccf (void)
{
    //REQUIRE (0 == test_ns2ccf_fix1());
    return -1;
}

#endif
