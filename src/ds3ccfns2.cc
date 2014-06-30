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

#ifndef USE_DS3NS2
#define USE_DS3NS2 1
#endif

#if USE_DS3NS2
#include <packet.h> // NS2
#include "hdr-docsis.h"

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
    ds3_packet_buffer_ns2_t *p = dynamic_cast<ds3_packet_buffer_ns2_t *>(macbuffer.get_buffer());
    assert (NULL != p);
    Packet *ns2pkt = p->extract_ns2pkt(0);
    assert (NULL != ns2pkt);

    // push to uplayer
    assert(0);
    return -1;
}


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

/**
 * @brief extract a Packet at the position pos
 *
 * @param pos : [in] the start position of a MAC packet header in the buffer
 *
 * @return the MAC packet created on success, NULL on error
 *
 */
Packet *
ds3_packet_buffer_ns2_t::extract_ns2pkt (size_t pos)
{
    ds3_packet_generic_t gp = ds3_packet_buffer_gpkt_t::extract_gpkt (pos);
    if (NULL == gp) {
        return NULL;
    }
    //Packet * np = (Packet *)gp;
    Packet * np = (Packet *)(gp); //dynamic_cast<Packet *>(gp);
    assert (NULL != np);
    // check the size of packet
    ssize_t ret;
    ret = ds3_packet_buffer_gpkt_t::block_size_at (pos);
    if (ret != (ssize_t)ns2pkt_get_size(np)) {
        // error
        assert (0);
        return NULL;
    }
    return np;
}

// can we get the lenght of a MAC packet
bool
ns2pkt_can_get_size (Packet *p, size_t pos_begin, size_t pos_end)
{
    if (pos_begin != 0) {
        return false;
    }
    if (pos_end < 2) {
        return false;
    }
    if (pos_end < 4) {
        return false;
    }
    struct hdr_docsis * dh = HDR_DOCSIS(p);
    if ((dh->dshdr().fc_type == 0x03) && (dh->dshdr().fc_parm == 0x04) && (dh->dshdr().ehdr_on == 0)) {
        if (pos_end < 5) {
            return false;
        }
    }
    return true;
}

/**
 * @brief get the byte size of a Packet, including the header and data
 *
 * @param p : [in] a NS2 Packet
 *
 * @return the byte size of packet, >0 on success, < 0 on error
 *
 */
size_t
ns2pkt_get_size (Packet *p)
{
    size_t len = 0;
    assert (NULL != p);
    struct hdr_docsis * dh = HDR_DOCSIS(p);
    len = 1 + 1 + 2 + dh->dshdr().len + 2; // regular length
    if ((dh->dshdr().fc_type == 0x03) && (dh->dshdr().fc_parm == 0x04) && (dh->dshdr().ehdr_on == 0)) {
        /* Queue-Depth based request, MAC_PARM is 2 bytes, not 1 byte */
        len ++;
    }
    return len;
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
    ds3_packet_generic_t gp = NULL;
    size_t pos_begin = 0;
    size_t pos_end = 0;
    if (false == ds3_packet_buffer_gpkt_t::get_gpkt_info(pos, gp, pos_begin, pos_end)) {
        assert (0);
        return -1;
    }
    Packet *p = (Packet *)gp;
    if (! ns2pkt_can_get_size (p, pos_begin, pos_end)) {
        return -1;
    }

    return ret;
}

#if CCFDEBUG
int
test_ns2ccf (void)
{
    //REQUIRE (0 == test_ns2ccf_fix1());
    return -1;
}
#endif

#endif

