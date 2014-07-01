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

int hdr_docsisccf::offset_;

static class MacDocsisCcfHeaderClass : public PacketHeaderClass
{
public:
    MacDocsisCcfHeaderClass() : PacketHeaderClass("PacketHeader/DocsisCcf", sizeof(hdr_docsisccf))
    {
        bind_offset(&hdr_docsisccf::offset_);
        std::cout << "Constructor:MacDocsisCcfHeaderClass: size allocated: " << sizeof(hdr_docsisccf) << std::endl;
    }
} class_hdr_docsisccf;

// get a grant from the data structure
// grant_type: DATA_GRANT/UGS_GRANT/UREQ_GRANT/CONTENTION_GRANT/
bool
ds3_ccf_pack_ns2_t::get_ns2_grant (unsigned char tbindex, int grant_type, ds3_grant_t & grant)
{
    assert (NULL != this->cm);
    double tm;
    int channel_id;
    tm = cm->timer_expiration(tbindex, grant_type, &channel_id);
    if (tm < 0) {
        return false;
    }
    switch (grant_type) {
    case DATA_GRANT:
    case UGS_GRANT:
        grant.set_size (this->cm->UpFlowTable[tbindex].curr_gsize);
        this->cm->UpFlowTable[tbindex].curr_gsize = 0;
        break;
    case UREQ_GRANT:
        assert (0);
        return false;
        break;
    case CONTENTION_GRANT:
        grant.set_size (this->cm->bytes_pminislot);
        break;
    }
    grant.set_time (this->current_time() + tm);
    grant.set_channel_id (channel_id);
    return true;
}

size_t
ds3_ccf_pack_ns2_t::get_ns2_piggyback (unsigned char tbindex)
{
    // TODO
    // get the value
    // reset the ns2 value to 0?
    return 0;
}

void
ds3_ccf_pack_ns2_t::add_more_grants (unsigned char tbindex)
{
    ds3_grant_t grant;
    for ( ; this->get_pktlst_size() > 0; ) {
        this->add_piggyback (this->get_ns2_piggyback (tbindex));
        if (this->get_ns2_grant (tbindex, DATA_GRANT, grant)) {
            this->add_grant (grant);
        } else {
            break;
        }
    }
}

int
ds3_ccf_pack_ns2_t::process_packet (unsigned char tbindex, Packet *ns2pkt)
{
    ds3packet_ns2mac_t *gp = new ds3packet_ns2mac_t ();
    assert (NULL != gp);

    hdr_cmn * chdr = hdr_cmn::access(ns2pkt);
    assert ((PT_DOCSIS <= chdr->ptype()) && (chdr->ptype() <= PT_DOCSISCONCAT));

    gp->set_ns2packet (ns2pkt);
    ds3_ccf_pack_t::process_packet (gp);
    this->add_more_grants (tbindex);
    return 0;
}

#define CCFMAGIC 0x0ccfccf0
typedef struct _ns2_ds3pkt_info_t {
    size_t ccfmagic;
    ds3packet_t *ccfpkt;
} ns2_ds3pkt_info_t;

int
ds3_ccf_pack_ns2_t::start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id)
{
    std::cout << "Got a packed CCF segment: " << std::endl;
    std::cout << "  -- start timer: tm=" << abs_time << ", event=" << ds3_event2desc(evt) << ", pkt.size=" << p->get_size() << ", channelId=" << channel_id << std::endl;

    ds3packet_ccf_t *ccfp = dynamic_cast<ds3packet_ccf_t *>(p);
    assert (NULL != ccfp);

    Packet *ns2pkt = Packet::alloc( sizeof (ns2_ds3pkt_info_t) );
    assert (NULL != ns2pkt);

    hdr_cmn * chdr = hdr_cmn::access(ns2pkt);
    assert (NULL != p);
    chdr->ptype() = PT_DOCSISCCF;
    chdr->size() = p->size();

    ns2_ds3pkt_info_t * pinfo = (ns2_ds3pkt_info_t *)ns2pkt->accessdata();
    assert (NULL != pinfo);
    pinfo->ccfmagic = CCFMAGIC;
    pinfo->ccfpkt = p;

    // TODO: send ns2pkt
    assert (0);
    return -1;
}

int
ds3_ccf_unpack_ns2_t::process_packet (Packet *ns2pkt)
{
    hdr_cmn * chdr = hdr_cmn::access(ns2pkt);
    assert (chdr->ptype() == PT_DOCSISCCF);

    ns2_ds3pkt_info_t * pinfo = (ns2_ds3pkt_info_t *)ns2pkt->accessdata();
    assert (pinfo->ccfmagic == CCFMAGIC);

    ds3packet_t *gp = pinfo->ccfpkt;
    assert (NULL != gp);
    Packet::free (ns2pkt);

    return ds3_ccf_unpack_t::process_packet (gp);
}

int
ds3_ccf_unpack_ns2_t::signify_packet (ds3_packet_buffer_t & macbuffer)
{
    assert (macbuffer.size() > 0);
    ds3_packet_buffer_ns2_t *p = dynamic_cast<ds3_packet_buffer_ns2_t *>(macbuffer.get_buffer());
    assert (NULL != p);
    Packet *ns2pkt = p->extract_ns2pkt(0);
    assert (NULL != ns2pkt);
    hdr_cmn * chdr = hdr_cmn::access(ns2pkt);
    assert ((PT_DOCSIS <= chdr->ptype()) && (chdr->ptype() <= PT_DOCSISCONCAT));

    // push ns2pkt to uplayer
    this->cmts->RecvFrame (ns2pkt, 0);
    return 0;
}

int
ds3_ccf_unpack_ns2_t::signify_piggyback (int sc, size_t request)
{
    std::cout << "Got a unpacked piggyback request: sc=" << sc << ", request=" << request << std::endl;
    //Packet *ns2pkt = NULL; //new Packet();
    //assert (NULL != ns2pkt);
    // TODO
    assert (0);
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

#endif /* USE_DS3NS2 */

