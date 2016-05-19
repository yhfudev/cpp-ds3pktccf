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
#include "mac-docsis.h" // NS2
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

/**
 * @brief extract a Packet at the position pos
 *
 * @param pgpkt : [in] the generic packet buffer pointer
 * @param pos : [in] the start position of a MAC packet header in the buffer
 *
 * @return the MAC packet created on success, NULL on error
 *
 */
Packet *
gpkt_extract_ns2pkt (ds3_packet_buffer_gpkt_t *pgpkt, size_t pos)
{
    assert (NULL != pgpkt);
    ds3_packet_generic_t gp = pgpkt->extract_gpkt (pos);
    if (NULL == gp) {
        return NULL;
    }
    //Packet * np = (Packet *)gp;
    Packet * np = (Packet *)(gp); //dynamic_cast<Packet *>(gp);
    assert (NULL != np);
    // check the size of packet
    ssize_t ret;
    ret = pgpkt->block_size_at (pos);
    if (ret != (ssize_t)ns2pkt_get_size(np)) {
        // error
        assert (0);
        return NULL;
    }
    return np;
}

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
    return gpkt_extract_ns2pkt(this, pos);
}

uint8_t &
ds3_packet_buffer_ns2_t::at(size_t i)
{
    static uint8_t t = -1;
    DS3_WRONGFUNC_RETVAL(t);
}

// get a grant from the data structure
// grant_type: DATA_GRANT/UGS_GRANT/UREQ_GRANT/CONTENTION_GRANT/
bool
ds3_ccf_pack_ns2_t::get_ns2_grant (unsigned char tbindex, int grant_type, ds3_grant_t & grant)
{
    assert (NULL != this->cm);
    double tm;
    int channel_id;
    assert (NULL != this->cm);
    tm = this->cm->timer_expiration(tbindex, grant_type, &channel_id);
    if (tm < 0) {
        return false;
    }
    switch (grant_type) {
    case DATA_GRANT:
    case UGS_GRANT:
        grant.set_size (this->cm->UpFlowTable[tbindex].curr_gsize);
        this->cm->UpFlowTable[tbindex].curr_gsize = 0;
        break;

    case CONTENTION_GRANT:
        grant.set_size (this->cm->bytes_pminislot);
        break;

    case UREQ_GRANT:
    default:
        assert (0);
        return false;
        break;
    }
    assert (grant.get_size() > 10);
    grant.set_size( 0.92 * grant.get_size() - 10 );
    grant.set_time (this->current_time() + tm);
    grant.set_channel_id (channel_id);
    return true;
}

size_t
ds3_ccf_pack_ns2_t::get_ns2_piggyback (unsigned char tbindex, int grant_type)
{
    assert (NULL != this->cm);
    size_t ret = this->cm->UpFlowTable[tbindex].frag_data;
    this->cm->UpFlowTable[tbindex].frag_data = 0;
    return ret;
}

void
ds3_ccf_pack_ns2_t::add_more_grants (unsigned char tbindex, int grant_type)
{
    ds3_grant_t grant;
    for ( ; this->get_pktlst_size() > 0; ) {
        this->add_piggyback (this->get_ns2_piggyback (tbindex, grant_type));
        if (this->get_ns2_grant (tbindex, grant_type, grant)) {
            this->add_grant (grant);
        } else {
            break;
        }
    }
}

int
ds3_ccf_pack_ns2_t::process_packet (Packet *ns2pkt)
{
    ds3packet_ns2mac_t *gp = new ds3packet_ns2mac_t ();
    assert (NULL != gp);

    hdr_cmn * chdr = HDR_CMN(ns2pkt);
    //assert ((PT_DOCSIS <= chdr->ptype()) && (chdr->ptype() <= PT_DOCSISCONCAT));

    // record mac address?
    if (this->mac_dest < 0) {
        struct hdr_mac* mh = HDR_MAC(ns2pkt);
        this->mac_dest = mh->macSA();
    } else {
        struct hdr_mac* mh = HDR_MAC(ns2pkt);
        assert (this->mac_dest == mh->macSA());
    }

    gp->set_ns2packet (ns2pkt);
    ds3_ccf_pack_t::process_packet (gp);
    this->add_more_grants (this->tbindex_, this->grant_type_);
    return 0;
}

/**
 * @brief check if (i < j)
 * @param i : the left hand of the value
 * @param j : the right hand of the value
 * @return true if (i < j), false otherwise
 */
inline bool
compare_sndpktp (ns2tm_sendpkt_info_t i, ns2tm_sendpkt_info_t j)
{
    return (i.time > j.time);
}

void
ns2timer_sending_t::expire_task (void)
{
    double curtime = Scheduler::instance().clock();
    std::vector<ns2tm_sendpkt_info_t>::iterator it = this->pktlist.begin();
    for ( ; this->pktlist.size() > 0; ) {
        if (curtime < this->pktlist[0].time) {
            break;
        }
        // expire it
        // check if the timer is accurate enough
        /*if (curtime > this->pktlist[0].time + 0.0000001) {
            assert (0);
        }*/
        std::cerr.precision(10);
        std::cout.precision(10);
        std::cerr << "ds3ns2: curtime=" << curtime << ", send packet tm=" << this->pktlist[0].time << " at channel " << this->pktlist[0].channel_id << std::endl;
        this->t_->MacSendFrame0 (this->pktlist[0].pkt, this->pktlist[0].channel_id);

        std::pop_heap (this->pktlist.begin(), this->pktlist.end(), compare_sndpktp);
        this->pktlist.pop_back();
    }
}

bool
ns2timer_sending_t::add_sending_task (Packet * pkt, size_t channel_id, double time)
{
    ns2tm_sendpkt_info_t rec;
    rec.pkt = pkt;
    rec.channel_id = channel_id;
    rec.time = time;

    double curtime = Scheduler::instance().clock();
    bool flg_changed = true;

    if (this->pktlist.size() > 0) {
        if (time < this->pktlist[0].time) {
            this->cancel();
            flg_changed = true;
        } else {
            flg_changed = false;
        }
        if (curtime >= this->pktlist[0].time) {
            assert (0); // error
            flg_changed = true;
            this->cancel();
        }
    }

    this->pktlist.push_back (rec);
    std::push_heap (this->pktlist.begin(), this->pktlist.end(), compare_sndpktp);
    this->expire_task ();
    if (this->pktlist.size () > 0) {
        if (flg_changed) {
            this->resched (this->pktlist[0].time - curtime);
        }
    } else {
        return false;
    }
    return true;
}

void
ns2timer_sending_t::expire (Event* evt)
{
    double curtime = Scheduler::instance().clock();
    this->expire_task();
    if (this->pktlist.size () > 0) {
        this->resched (this->pktlist[0].time - curtime);
    }
}

int
ds3_ccf_pack_ns2_t::start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id)
{
    std::cout << "Got a packed CCF segment: " << std::endl;
    std::cout << "  -- start timer: tm=" << abs_time << ", event=" << ds3_event2desc(evt) << ", pkt.size=" << p->get_size() << ", channelId=" << channel_id << std::endl;

    ds3packet_ccf_t * ccfp = dynamic_cast<ds3packet_ccf_t * >(p);
    assert (NULL != ccfp);

    Packet * ns2pkt = PACKET_ALLOCN ( sizeof (ns2_ds3pkt_info_t) );
    assert (NULL != ns2pkt);

    hdr_cmn * chdr = HDR_CMN(ns2pkt);
    assert (NULL != p);
    chdr->ptype() = PT_DOCSISCCF;
    chdr->size() = p->size();
    chdr->direction() = hdr_cmn::DOWN;

    ns2_ds3pkt_info_t * pinfo = (ns2_ds3pkt_info_t *)ns2pkt->accessdata();
    assert (NULL != pinfo);
    pinfo->ccfmagic = CCFMAGIC;
    pinfo->ccfpkt = p;
    assert (this->mac_dest >= 0);
    pinfo->mac_dest = this->mac_dest;

    // send ns2pkt
    this->tmr_send.add_sending_task (ns2pkt, channel_id, abs_time);
    assert (NULL != this->cm);
    return 0;
}

int
ds3_ccf_unpack_ns2_t::process_packet (Packet * ns2pkt)
{
    hdr_cmn * chdr = HDR_CMN(ns2pkt);
    assert (chdr->ptype() == PT_DOCSISCCF);
    // debug:
    std::cerr << __func__ << " recv ns2pkt " << ( (hdr_cmn::DOWN == chdr->direction()) ? "cmn::DOWN" : "cmn::UP" ) << std::endl;

    ns2_ds3pkt_info_t * pinfo = (ns2_ds3pkt_info_t * )ns2pkt->accessdata();
    assert (pinfo->ccfmagic == CCFMAGIC);

    ds3packet_t * gp = pinfo->ccfpkt;
    assert (NULL != gp);
    Packet::free (ns2pkt);

    return ds3_ccf_unpack_t::process_packet (gp);
}

int
ds3_ccf_unpack_ns2_t::signify_packet (ds3_packet_buffer_t & macbuffer)
{
    assert (macbuffer.size() > 0);
#define USE_DS3NS2_BUF 0
#if USE_DS3NS2_BUF
    ds3_packet_buffer_ns2_t *p = dynamic_cast<ds3_packet_buffer_ns2_t *>(macbuffer.get_buffer());
    ds3_packet_buffer_gpkt_t *p0 = dynamic_cast<ds3_packet_buffer_gpkt_t *>(macbuffer.get_buffer());
    assert (NULL != p0);
#else
    ds3_packet_buffer_gpkt_t *p = dynamic_cast<ds3_packet_buffer_gpkt_t *>(macbuffer.get_buffer());
    ds3_packet_buffer_ns2_t *p0 = dynamic_cast<ds3_packet_buffer_ns2_t *>(macbuffer.get_buffer());
    assert (NULL == p0);
#endif
    assert (NULL != p);
    if (NULL == p) {
        std::cerr << "ds3ccf: Fatal Error, packet buffer type" << std::endl;
        assert (0);
        return -1;
    }
#if USE_DS3NS2_BUF
    Packet *ns2pkt = p->extract_ns2pkt(0);
#else
    Packet *ns2pkt = gpkt_extract_ns2pkt(p, 0);
#endif
    assert (NULL != ns2pkt);
    if (NULL == p) {
        std::cerr << "ds3ccf: Fatal Error, packet buffer data" << std::endl;
        assert (0);
        return -1;
    }
    hdr_cmn * chdr = HDR_CMN(ns2pkt);
    chdr->direction() = hdr_cmn::UP;
    //assert ((PT_DOCSIS <= chdr->ptype()) && (chdr->ptype() <= PT_DOCSISCONCAT));

    // push ns2pkt to uplayer
    assert (NULL != this->cmts);
    this->cmts->RecvFrame (ns2pkt, 0);
    return 0;
}

int
ds3_ccf_unpack_ns2_t::signify_piggyback (int sc, size_t request)
{
    std::cout << "Got a unpacked piggyback request: sc=" << sc << ", request=" << request << std::endl;
    assert (NULL != this->cmts);
    this->cmts->process_piggyback (sc, request);
    return 0;
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
    struct hdr_cmn* cmnhdr = HDR_CMN(p);
    assert (len == (size_t)cmnhdr->size());
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

ssize_t
ds3packet_ns2mac_t::to_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    if (0 == szbuf) {
        return ns2pkt_get_size((Packet *)this->get_packet ());
    }
    assert (0);
    return -1;
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

