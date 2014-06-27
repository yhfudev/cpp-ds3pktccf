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

bool
ds3_packet_buffer_gpkt_t::get_gpkt_info (size_t pos /* IN */, ds3_packet_generic_t & ret_pkt /* OUT */, size_t & ret_begin /* OUT */, size_t & ret_end /* OUT */)
{
    size_t szcur = 0;
    size_t i = 0;
    // find the the position in the packet list that the total size of the previous packets is <= the required position.
    for (i = 0; (szcur < pos)  && (i < this->pktlist.size()); i ++) {
        szcur += this->pktlist[i].sz;
    }
    if (szcur < pos) {
        return NULL;
    }
    if (szcur != pos) {
        assert (szcur > pos);
        i --;
        szcur -= this->pktlist[i].sz;
    }
    // skip 0 size packets
    for (; (this->pktlist[i].sz < 1)  && (i < this->pktlist.size()); i ++) {
    }
    ret_pkt = this->pktlist[i].pkt;
    ret_begin = this->pktlist[i].pos + (pos - szcur);
    ret_end = this->pktlist[i].pos + this->pktlist[i].sz;
    assert (ret_begin <= ret_end);
    return true;
}

ds3_packet_generic_t
ds3_packet_buffer_gpkt_t::extract_gpkt (size_t pos)
{
    size_t szcur = 0;
    size_t i = 0;
    for (i = 0; (szcur < pos)  && (i < this->pktlist.size()); i ++) {
        szcur += this->pktlist[i].sz;
    }
    if (szcur < pos) {
        return NULL;
    }
    assert (szcur == pos);
    // check the size of the data
    if (0 == this->pktlist[i].pos) {
#if CCFDEBUG
        if (this->pktlist[i].flg_extracted) {
            std::cerr << "Warning: try to re-extract the same packet: pkt=" << this->pktlist[i].pkt << ", pkt.segpos=" << this->pktlist[i].pos << ", pkt.segsize=" << this->pktlist[i].sz << std::endl;
        }
        this->pktlist[i].flg_extracted = true;
#endif
        return this->pktlist[i].pkt;
    }
    assert (0);
    return NULL;
}

bool
ds3_packet_buffer_gpkt_t::erase (size_t begin_self, size_t end_self)
{
    if ((ssize_t)begin_self >= this->size()) {
        return false;
    }
    if ((ssize_t)end_self > this->size()) {
        end_self = this->size();
    }
    if (begin_self == end_self) {
        return true;
    }
    size_t szcur = 0;
    size_t i = 0;
    for (i = 0; (szcur < begin_self)  && (i < this->pktlist.size()); i ++) {
        szcur += this->pktlist[i].sz;
    }
    if (szcur != begin_self) {
        assert (szcur > begin_self);
        i --;
        szcur -= this->pktlist[i].sz;
    }

    ds3pktbufns2_info_t pi;
    size_t pos_cur = begin_self;
    for (; szcur < end_self;) {
        assert (pos_cur >= szcur);
        // the part to be delete
        size_t this_pktlist_i_sz = this->pktlist[i].sz; // backup the size
        pi.pos = this->pktlist[i].pos + (pos_cur - szcur);
        pi.sz = this->pktlist[i].sz;
        pi.sz -= (pi.pos - this->pktlist[i].pos);
        // is the end_self is small that not reach to the end of this block?
        if (end_self < pos_cur + pi.sz) {
            pi.sz = end_self - pos_cur;
        }
        if (pi.pos + pi.sz >= this->pktlist[i].pos + this->pktlist[i].sz) {
            // remove the right part of this packet
            this->pktlist[i].sz -= pi.sz;
            if (this->pktlist[i].sz < 1) {
                // remove the whole packet
                this->pktlist.erase(this->pktlist.begin() + i);
            } else {
                i ++;
            }
        } else {
            // remove middle of the packet
            assert (pi.pos + pi.sz < this->pktlist[i].pos + this->pktlist[i].sz);
            if (pi.pos == this->pktlist[i].pos) {
                // remove the left part
                this->pktlist[i].sz -= pi.sz;
                this->pktlist[i].pos += pi.sz;
            } else {
                assert (pi.pos > this->pktlist[i].pos);
                ds3pktbufns2_info_t pi2;
                memmove (&pi2, &(this->pktlist[i]), sizeof (pi2));
                pi2.sz = (pi.pos - this->pktlist[i].pos);
                assert ((this->pktlist[i].pos + this->pktlist[i].sz) >= (pi.pos + pi.sz));
                this->pktlist[i].sz = (this->pktlist[i].pos + this->pktlist[i].sz) - (pi.pos + pi.sz);
                this->pktlist[i].pos = pi.pos + pi.sz;
                std::vector<ds3pktbufns2_info_t>::iterator it = this->pktlist.begin() + i;
                this->pktlist.insert(it, pi2);
                i ++;
            }
            assert (szcur + this_pktlist_i_sz > pos_cur + pi.sz);
        }
        szcur += this_pktlist_i_sz;
        pos_cur += pi.sz;
        assert (this->szpkt >= pi.sz);
        this->szpkt -= pi.sz;
    }

    return true;
}

// i = the index of insecting position
// szcur = the size of data before this one
bool
ds3_packet_buffer_gpkt_t::insert_gpkt_idx (size_t i, size_t szcur, size_t pos_self, ds3_packet_generic_t pkt, size_t begin_peer, size_t end_peer)
{
    if (begin_peer == end_peer) {
        return 0;
    }
    ds3pktbufns2_info_t pi;
    pi.pkt = pkt;
    pi.pos = begin_peer;
    assert (end_peer >= begin_peer);
    pi.sz  = end_peer - begin_peer;
#if CCFDEBUG
    pi.flg_extracted = false;

    size_t idx_merge = 0;
    if (i == this->pktlist.size()) {
        assert (szcur == this->szpkt);
    }
#endif // DEBUG
    if (szcur == pos_self) {
        // check if we can merge the new one with previous one
        bool flg_merged = false;
        assert ((0 <= i) && (i <= this->pktlist.size()));
        if (i > 0) {
            if (this->pktlist[i-1].pkt == pi.pkt) {
                // check the data range
                if (this->pktlist[i-1].pos + this->pktlist[i-1].sz > pi.pos) {
                    assert (0);
                    return false;
                } else if (this->pktlist[i-1].pos + this->pktlist[i-1].sz == pi.pos) {
                    this->pktlist[i-1].sz += pi.sz;
                    flg_merged = true;
#if CCFDEBUG
                    idx_merge = i - 1;
#endif
                }
            }
        }
        if (i < this->pktlist.size()) {
            if (pi.pkt == this->pktlist[i].pkt) {
                // check the data range
                if (pi.pos + pi.sz > this->pktlist[i].pos) {
                    assert (0);
                    return false;
                } else if (pi.pos + pi.sz == this->pktlist[i].pos) {
                    if (flg_merged) {
                        // we already merged with previous one, then merge [i-1] and [i]
                        assert (i > 0);
                        this->pktlist[i-1].sz += this->pktlist[i].sz;
                        std::vector<ds3pktbufns2_info_t>::iterator it = pktlist.begin() + i;
                        this->pktlist.erase(it);
#if CCFDEBUG
                        this->pktlist[i-1].flg_extracted = (this->pktlist[i-1].flg_extracted | this->pktlist[i].flg_extracted);
#endif
                    } else {
                        this->pktlist[i].sz += pi.sz;
                        this->pktlist[i].pos = pi.pos;
#if CCFDEBUG
                        idx_merge = i;
#endif
                    }
                    flg_merged = true;
                }
            }
        }
        if (! flg_merged) {
            std::vector<ds3pktbufns2_info_t>::iterator it = pktlist.begin() + i;
            this->pktlist.insert(it, pi);
        }
#if CCFDEBUG
        else if (this->pktlist[idx_merge].flg_extracted) {
            std::cerr << "Warning: try to merged the extracted packet: pkt=" << this->pktlist[idx_merge].pkt << ", pkt.segpos=" << this->pktlist[idx_merge].pos << ", pkt.segsize=" << this->pktlist[idx_merge].sz << std::endl;
        }
#endif
        this->szpkt += pi.sz;
        return true;
    } /* szcur == pos_self */
    assert (szcur > pos_self);
    // TODO: in the middle of a packet, we need to split first and then insert the new one
    assert (i > 0);
    i --;
    szcur -= this->pktlist[i].sz;
    if (pkt == this->pktlist[i].pkt) {
        assert (pos_self > szcur);
        if (this->pktlist[i].pos + (pos_self - szcur) == pi.pos) {
            // insert only one packet
            size_t sz_pi_bak = pi.sz;
            // the packet to be inserted
            pi.pos = this->pktlist[i].pos;
            pi.sz += (pos_self - szcur);
#if CCFDEBUG
            pi.flg_extracted = this->pktlist[i].flg_extracted;
#endif
            // update the current
            this->pktlist[i].pos += ((pos_self - szcur) + sz_pi_bak);
            this->pktlist[i].sz -= (pos_self - szcur);

            std::vector<ds3pktbufns2_info_t>::iterator it = pktlist.begin() + i;
            this->pktlist.insert(it, pi);
            this->szpkt += pi.sz;
            return true;
        }
    }
    // split the current packet to two segments
    // insert the new one between them
    ds3pktbufns2_info_t pi2;
    memmove (&pi2, &(this->pktlist[i]), sizeof (pi2));
    pi2.pos = this->pktlist[i].pos;
    pi2.sz  = (pos_self - szcur);
    this->pktlist[i].pos += (pos_self - szcur);
    this->pktlist[i].sz -= (pos_self - szcur);
    std::vector<ds3pktbufns2_info_t>::iterator it = pktlist.begin() + i;
    this->pktlist.insert(it, pi);
    it = pktlist.begin() + i;
    this->pktlist.insert(it, pi2);

    this->szpkt += pi.sz;
    return true;
}

bool
ds3_packet_buffer_gpkt_t::insert_gpkt (size_t pos_self, ds3_packet_generic_t pkt, size_t begin_peer, size_t end_peer)
{
    size_t szcur = 0;
    size_t i = 0;

    if (begin_peer == end_peer) {
        return 0;
    }

    assert (pos_self <= this->szpkt);
    for (i = 0; (szcur < pos_self)  && (i < this->pktlist.size()); i ++) {
        szcur += this->pktlist[i].sz;
    }
    return this->insert_gpkt_idx (i, szcur, pos_self, pkt, begin_peer, end_peer);
}

ds3_packet_buffer_t *
ds3_packet_buffer_gpkt_t::insert_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self)
{
    DS3_DYNCST_CHKRET_CONTENT_POINTER(ds3_packet_buffer_gpkt_t, arg_peer);
    assert (NULL != peer);
    // TODO: add the content between [begin_self, end_self) to peer
    // find the start position
    ds3pktbufns2_info_t pi;

    size_t szcur = 0;
    size_t i = 0;
    size_t szcurj = 0;
    size_t j = 0;

    assert (begin_self <= this->szpkt);
    szcurj = 0;
    for (j = 0; (szcur < begin_self)  && (j < this->pktlist.size()); j ++) {
        szcurj += this->pktlist[j].sz;
    }
    if (szcurj > begin_self) {
        assert (j > 0);
        j --;
        szcurj -= this->pktlist[j].sz;
    }
    szcur = 0;
    for (i = 0; (szcur < pos_peer)  && (i < peer->pktlist.size()); i ++) {
        szcur += peer->pktlist[i].sz;
    }
    size_t pos_cur = begin_self;
    for (; szcurj < end_self;) {
        assert (pos_cur >= szcurj);
        pi.pos = this->pktlist[j].pos + (pos_cur - szcurj);
        pi.sz = this->pktlist[j].sz;
        pi.sz -= (pi.pos - this->pktlist[j].pos);
        if (end_self < pos_cur + pi.sz) {
            pi.sz = end_self - pos_cur;
        }
        peer->insert_gpkt_idx (i, szcur, pos_peer, pi.pkt, pi.pos, pi.pos + pi.sz);
        szcurj += this->pktlist[j].sz;
        pos_cur += pi.sz;
        j ++;
        i ++;
        pos_peer += pi.sz;
        szcur += pi.sz;
    }
    assert (0);
    return arg_peer;
}

ds3_packet_buffer_t *
ds3_packet_buffer_gpkt_t::copy_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self)
{
    DS3_DYNCST_CHKRET_CONTENT_POINTER(ds3_packet_buffer_gpkt_t, arg_peer);
    assert (NULL != peer);
    // TODO: copy the content between [begin_self, end_self) to peer
    if ((ssize_t)begin_self >= this->size()) {
        return NULL;
    }
    if ((ssize_t)end_self > this->size()) {
        return NULL;
    }
    if (begin_self == end_self) {
        return arg_peer;
    }
    size_t pos_end = peer->end();
    if (pos_end > pos_peer + (end_self - begin_self)) {
        pos_end = pos_peer + (end_self - begin_self);
    }
    if (! peer->erase (pos_peer, pos_end)) {
        assert (0);
        return NULL;
    }
    return this->insert_to(pos_peer, peer, begin_self, end_self);
}

#if 1
ds3_packet_buffer_gpkt_t::ds3_packet_buffer_gpkt_t(ds3_packet_buffer_t *arg_peer, size_t begin, size_t end)
: szpkt(0)
{
    ds3_packet_buffer_gpkt_t * peer = dynamic_cast<ds3_packet_buffer_gpkt_t *> (arg_peer);
    assert (NULL != peer);
    ds3_packet_buffer_t * ret = peer->insert_to(0, this, begin, end);
    assert (ret == this);
}

#else
ds3_packet_buffer_gpkt_t::ds3_packet_buffer_gpkt_t(ds3_packet_buffer_t *arg_peer, size_t begin, size_t end)
{
    ds3_packet_buffer_gpkt_t * peer = dynamic_cast<ds3_packet_buffer_gpkt_t *> (arg_peer);
    assert (NULL != peer);
    if (end < begin) {
        return;
    }
    if (begin >= (peer->pktlist).size()) {
        return;
    }
    if (end > (peer->pktlist).size()) {
        end = (peer->pktlist).size();
    }
    this->pktlist.resize (0);
    //std::copy (peer->buffer.begin() + begin, peer->buffer.begin() + end, this->buffer.begin());
    this->pktlist.insert (this->pktlist.begin(), peer->pktlist.begin() + begin, peer->pktlist.begin() + end);
    this->szpkt = peer->szpkt;
}
#endif

int
ds3_packet_buffer_gpkt_t::resize(size_t sznew)
{
    if ((ssize_t)sznew > this->size()) {
        assert (0);
        return -1;
    }
    if ((ssize_t)sznew == this->size()) {
        return 0;
    }
    if (this->erase(sznew, this->size())) {
        return 0;
    }
    assert (0); // TODO
    return -1;
}

ssize_t
ds3_packet_buffer_gpkt_t::size(void) const
{
    return this->szpkt;
}

uint8_t &
ds3_packet_buffer_gpkt_t::at(size_t i)
{
    static uint8_t t = -1;
    DS3_WRONGFUNC_RETVAL(t);
}

ssize_t
ds3_packet_buffer_gpkt_t::block_size_at (size_t pos)
{
    // size of sub-block (including header+content)
    size_t szcur = 0;
    size_t i = 0;
    for (i = 0; (szcur < pos)  && (i < this->pktlist.size()); i ++) {
        szcur += this->pktlist[i].sz;
    }
    if (szcur == pos) {
        return (this->pktlist[i].sz);
    }
    assert (0); // TODO
    return -1;
}

ssize_t
ds3_packet_buffer_gpkt_t::to_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    assert (0); // TODO
    return -1;
}

ssize_t
ds3_packet_buffer_gpkt_t::from_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    assert (0); // TODO
    return -1;
}

#if CCFDEBUG
void
ds3_packet_buffer_gpkt_t::dump (void)
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
ds3packet_gpkt_t::dump (void)
{
    this->dump_content ();
}
#endif

#if CCFDEBUG
ssize_t
ds3packet_gpkt_t::to_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    ssize_t szret = -1;
    assert (0); // TODO:
    return szret;
}

ssize_t
ds3packet_gpkt_t::from_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    ssize_t szret = -1;
    assert (0); // TODO:
    return szret;
}

ssize_t
ds3packet_gpkt_t::from_nbs (ds3_packet_buffer_t *peer, size_t pos_peer)
{
    ssize_t szret = -1;
    assert (0); // TODO:
    return szret;
}
#endif

ds3_packet_buffer_t *
ds3packet_gpkt_t::insert_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self)
{
    DS3_DYNCST_CHKRET_DS3PKT_BUFFER(ds3_packet_buffer_gpkt_t, arg_peer);
    assert (NULL != peer);

    if (begin_self >= end_self) {
        return arg_peer;
    }
    if (false == peer->insert_gpkt (pos_peer, this->pkt, begin_self, end_self)) {
        if (flg_peer_is_new) { free (peer); }
        return NULL;
    }
    return arg_peer;
}

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

#include <iostream>     // std::cout, std::endl
#include <iomanip>      // std::setfill, std::setw

#include "testmac.h"

#ifndef REQUIRE
#define REQUIRE(a) if (! (a)) { assert(a); return -1; }
#endif

/**
 * @brief the packet content class for NS2 Packet class
 */
class ds3_packet_buffer_test_t : public ds3_packet_buffer_gpkt_t {
public:
#if CCFDEBUG
    virtual void dump (void);
#endif
    ds3packet_nbsmac_t * extract_testpkt (size_t pos); // extract a Packet at the position pos,

    virtual uint8_t & at(size_t i);
    ds3_packet_buffer_test_t() {}
    virtual ssize_t block_size_at (size_t pos);
    DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS_MINI(ds3_packet_buffer_test_t);
};

inline ds3_packet_buffer_test_t::ds3_packet_buffer_test_t(ds3_packet_buffer_t *peer, size_t begin, size_t end)
    : ds3_packet_buffer_gpkt_t (peer, begin, end) { }

inline ds3_packet_buffer_test_t::~ds3_packet_buffer_test_t() {}

/** @brief test packet class for ds3packet_nbsmac_t */
class ds3packet_testmac_t : public ds3packet_gpkt_t {
public:
#if CCFDEBUG
    virtual void dump (void);
    virtual uint8_t & at(size_t i);
#endif
    void set_testpacket (ds3packet_nbsmac_t *pkt1) { size_t sz = pkt1->size(); set_packet((ds3_packet_generic_t)pkt1, sz); }
};


#if CCFDEBUG
void
ds3_packet_buffer_test_t::dump (void)
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
ds3packet_testmac_t::dump (void)
{
    this->dump_content ();
}

uint8_t &
ds3packet_testmac_t::at(size_t i)
{
    static uint8_t t = -1;
    //ds3packet_nbsmac_t
    DS3_WRONGFUNC_RETVAL(t);
}

#endif

ds3packet_nbsmac_t *
ds3_packet_buffer_test_t::extract_testpkt (size_t pos)
{
    ds3_packet_generic_t gp = extract_gpkt (pos);
    if (NULL == gp) {
        return NULL;
    }
    //Packet * np = (Packet *)gp;
    ds3packet_nbsmac_t * np = (ds3packet_nbsmac_t *)(gp); //dynamic_cast<Packet *>(gp);
    assert (NULL != np);
    // check the size of packet
    ssize_t ret;
    ret = ds3_packet_buffer_gpkt_t::block_size_at (pos);
    if (ret != (ssize_t)np->size()) {
        // error
        assert (0);
        return NULL;
    }
    return np;
}

ssize_t
ds3_packet_buffer_test_t::block_size_at (size_t pos)
{
    ssize_t ret;
    ret = ds3_packet_buffer_gpkt_t::block_size_at (pos);
    if (ret < 0) {
        return -1;
    }
    // check the size of packet
    if (NULL == this->extract_testpkt(pos)) {
        assert (0);
        return -1;
    }
    return ret;
}

uint8_t &
ds3_packet_buffer_test_t::at(size_t i)
{
    static uint8_t t = -1;
    ds3_packet_generic_t p0 = NULL;
    size_t pos_begin = 0;
    size_t pos_end = 0;
    if (! this->get_gpkt_info (i, p0, pos_begin, pos_end)) {
        assert (0);
        return t;
    }
    ds3packet_nbsmac_t * p = (ds3packet_nbsmac_t *)(p0);
    if (NULL == p) {
        assert (0);
        return t;
    }
    return p->at(pos_begin);
}

#define EXECODE_ERASE       0x00
#define EXECODE_INSERT_FROM 0x01
#define EXECODE_COPY_FROM   0x02
#define EXECODE_INSERT_SELF 0x03
#define EXECODE_COPY_SELF   0x04
#define EXECODE_LAST   EXECODE_COPY_FROM
#define EXECODE_SIZE   (EXECODE_LAST + 1)

const char *
ds3_test_exec2desc (int e)
{
#define MYCASE(v) case v: return #v
    switch (e) {
        MYCASE(EXECODE_INSERT_FROM);
        MYCASE(EXECODE_INSERT_SELF);
        MYCASE(EXECODE_COPY_FROM);
        MYCASE(EXECODE_COPY_SELF);
        MYCASE(EXECODE_ERASE);
    }
    return "EXECODE_UNKNOWN";
#undef MYCASE
}

typedef struct _ds3_test_exec_info_t {
    int exec;
    ssize_t sq;
    ssize_t maxsz;       /* max size of the data content (DATA) */
    ssize_t range_begin; /* the begin position of the raw packet (HDR+DATA) */
    ssize_t range_end;   /* the end position of the raw packet (HDR+DATA) */
    ssize_t pos_self;
} ds3_test_exec_info_t;
#define SVAL_NA (-1)

#define MAX_SIZE_PKT 238

int
test_ns2ccf_gp (ds3_test_exec_info_t *pinfo, size_t numpi)
{
    std::vector<uint8_t> buf_stdvec;
    ds3_packet_buffer_test_t buf_gpkt;
    ds3_packet_buffer_nbsmac_t buf_nbs;

    ds3packet_nbsmac_t * pktnew = NULL;
    std::vector<ds3packet_nbsmac_t *> pktlist;

    size_t szmaxpkt = 0;
    uint16_t sequence = 0;
    std::vector<uint8_t> buf_fillcontent;
    ds3hdr_mac_t machdr;
    uint8_t macbuf[10];
    size_t szhdr = 0;
    size_t i;
    size_t j;
    for (i = 0; i < MAX_SIZE_PKT; i ++) {
        buf_fillcontent.push_back(0x10 + i);
    }

    std::vector<uint8_t>::iterator itb;
    std::vector<uint8_t>::iterator ite;
    ds3_packet_buffer_nbs_t nbscnt;
    std::vector<uint8_t> buf_tmp;
    bool flg_error = false;
    bool flg_skip = false;
    ds3_test_exec_info_t execinfo;

    //srand(0); // srand (time(NULL));

    for (i = 0; i < numpi; ) {
        // test ds3_packet_buffer_gpkt_t
        if (NULL == pinfo) {
            memset (&execinfo, 0, sizeof(execinfo));
            execinfo.sq = SVAL_NA;
            execinfo.maxsz = SVAL_NA;
            execinfo.range_begin = SVAL_NA;
            execinfo.range_end = SVAL_NA;
            execinfo.pos_self = SVAL_NA;
            execinfo.exec = rand () % EXECODE_SIZE;
        } else {
            memmove (&execinfo, pinfo + i, sizeof (execinfo));
        }
        std::cout << "Next Exec Code: " << ds3_test_exec2desc(execinfo.exec) << std::endl;

        switch (execinfo.exec) {
        case EXECODE_INSERT_FROM:
            // insert a new packet
            //  1. insert raw packet to std::vector<uint8_t>
            //  2. insert a new nbsmac packet to nbsmac
            //  3. insert a new nbsmac packet to gpkt
            //  4. compare all of the packet with std::vector<uint8_t>
            //     make sure they are equal of contents (except the header of first packet).
            if (NULL == pinfo) {
                execinfo.sq    = sequence; sequence ++;
                execinfo.maxsz = rand () % (buf_fillcontent.size() + 1);
            }

            assert (execinfo.maxsz <= (ssize_t)buf_fillcontent.size());

            memset (&machdr, 0, sizeof(machdr));
            machdr.sequence = execinfo.sq;
            machdr.length   = execinfo.maxsz;
            szhdr = ds3hdr_mac_to_nbs(macbuf, sizeof(macbuf), &machdr);

            buf_tmp.resize(0);
            buf_tmp.insert (buf_tmp.end(), macbuf, macbuf + szhdr);
            buf_tmp.insert (buf_tmp.end(), buf_fillcontent.begin(), buf_fillcontent.begin() + execinfo.maxsz);

            assert (buf_tmp.size() > 0);

            szhdr = ds3hdr_mac_to_nbs(NULL, 0, &machdr);
            assert (sizeof(macbuf) >= szhdr);
            assert (szhdr + execinfo.maxsz > 0);

            /**
             * make sure that the inserted position is not in the mac header area of the first packet
             * since we need to handle the packets overlay (for testing ds3packet_nbsmac_t)
             */
            assert ((ssize_t)szhdr == ds3hdr_mac_to_nbs(NULL, 0, &machdr));
            if (NULL == pinfo) {
                execinfo.pos_self = rand () % (buf_stdvec.size() + 1);
                if (buf_stdvec.size() > 0) {
                    assert (buf_stdvec.size() > szhdr);
                    assert ((buf_stdvec.size() - szhdr + 1) + szhdr > 0);
                    execinfo.pos_self = rand () % (buf_stdvec.size() - szhdr + 1) + szhdr;
                }
            }

            szmaxpkt = buf_tmp.size();
            assert ((ssize_t)szhdr == ds3hdr_mac_to_nbs(NULL, 0, &machdr));
            if (NULL == pinfo) {
                assert (szmaxpkt > 0);
                execinfo.range_begin = rand () % szmaxpkt;
                execinfo.range_end = rand () % szmaxpkt; // the size
                if (execinfo.range_begin + execinfo.range_end > (ssize_t)szmaxpkt) {
                    execinfo.range_end = szmaxpkt;
                } else {
                    execinfo.range_end = execinfo.range_begin + execinfo.range_end;
                }
                if (buf_stdvec.size() < szhdr) {
                    assert (buf_stdvec.size() == 0);
                    execinfo.pos_self = 0;
                    execinfo.range_begin = 0;
                    execinfo.range_end = execinfo.range_begin + szhdr + execinfo.maxsz;
                }
            }
            assert (execinfo.range_begin < (ssize_t)szmaxpkt);
            assert (execinfo.range_end <= (ssize_t)szmaxpkt);

            if (buf_stdvec.size() >= szhdr) {
                std::cout << "pos_self=" << execinfo.pos_self << ", szhdr=" << szhdr << std::endl;
                assert (execinfo.pos_self >= (ssize_t)szhdr);
            } else {
                assert (buf_stdvec.size() == 0);
                assert (execinfo.pos_self == 0);
                assert (execinfo.range_begin == 0);
                assert (execinfo.range_end == execinfo.range_begin + execinfo.maxsz + (ssize_t)szhdr);
            }

            std::cout << std::dec << "[" << i << "] insert sq " << execinfo.sq
                << " sz " << (execinfo.range_end - execinfo.range_begin) << " ofmaxsz " << execinfo.maxsz
                << " range [" << execinfo.range_begin << "," << execinfo.range_end << ")"
                << " at " << execinfo.pos_self
                << std::endl;

            std::cerr << std::dec << "    /*" << i << "*/{ "
                << ds3_test_exec2desc(execinfo.exec) << ", "
                << execinfo.sq          << " /* sq */, "
                << execinfo.maxsz       << " /* maxsz */, "
                << execinfo.range_begin << " /* range_begin */, "
                << execinfo.range_end   << " /* range_end */, "
                << execinfo.pos_self    << " /* pos_self */, "
                << "}," << std::endl;

            // vector buffer
            buf_stdvec.insert (buf_stdvec.begin() + execinfo.pos_self, buf_tmp.begin() + execinfo.range_begin, buf_tmp.begin() + execinfo.range_end);

            pktnew = new ds3packet_nbsmac_t();
            itb = buf_fillcontent.begin();
            ite = buf_fillcontent.begin() + machdr.length;
            nbscnt.resize(0);
            nbscnt.append(itb, ite);
            pktnew->set_content (&nbscnt);
            pktnew->sethdr_sequence(machdr.sequence);
            pktlist.push_back(pktnew); // backup the pointer

            // ds3packet
            //ssize_t ds3_packet_buffer_t::insert (size_t pos_self, ds3_packet_buffer_t *peer, size_t begin_peer, size_t end_peer);
            //buf_nbs.insert (pos_self, peer1, begin1, end1);

            // generic packet
            //bool ds3_packet_buffer_gpkt_t::insert_gpkt (size_t pos_self, ds3_packet_generic_t peer_pkt, size_t begin_peer, size_t end_peer);
            assert (execinfo.range_begin < (ssize_t)pktnew->size());
            assert (execinfo.range_end <= (ssize_t)pktnew->size());
            buf_gpkt.insert_gpkt(execinfo.pos_self, pktnew, execinfo.range_begin, execinfo.range_end);

            break;

        case EXECODE_COPY_SELF:
            szmaxpkt = buf_stdvec.size();
            if (szmaxpkt < 1) {
                flg_skip = true;
                break;
            }
            assert ((ssize_t)szhdr == ds3hdr_mac_to_nbs(NULL, 0, &machdr));
            if (NULL == pinfo) {
                assert (szmaxpkt > 0);
                execinfo.range_begin = rand () % szmaxpkt;
                execinfo.range_end = rand () % szmaxpkt; // the size
                if (execinfo.range_begin + execinfo.range_end > (ssize_t)szmaxpkt) {
                    execinfo.range_end = szmaxpkt;
                } else {
                    execinfo.range_end = execinfo.range_begin + execinfo.range_end;
                }
            }
            assert (execinfo.range_begin < (ssize_t)szmaxpkt);
            assert (execinfo.range_end <= (ssize_t)szmaxpkt);
            execinfo.pos_self = rand () % (szmaxpkt - szhdr) + szhdr;

            std::cout << std::dec << "[" << i << "] copy self to " << execinfo.pos_self
                << " from pos " << execinfo.pos_self
                << " tobegin " << execinfo.range_begin
                << " toend "   << execinfo.range_end
                << std::endl;

            std::cerr << std::dec << "    /*" << i << "*/{ "
                << ds3_test_exec2desc(execinfo.exec) << ", "
                << execinfo.sq          << " /* sq */, "
                << execinfo.maxsz       << " /* maxsz */, "
                << execinfo.range_begin << " /* range_begin */, "
                << execinfo.range_end   << " /* range_end */, "
                << execinfo.pos_self    << " /* pos_self */, "
                << "}," << std::endl;

            std::copy (buf_stdvec.begin() + execinfo.range_begin, buf_stdvec.begin() + execinfo.range_end, buf_stdvec.begin() + execinfo.pos_self);
            // ssize_t ds3_packet_buffer_t::copy (size_t pos_self, ds3_packet_buffer_t *peer, size_t begin_peer, size_t end_peer);
            buf_gpkt.copy (execinfo.pos_self, &buf_gpkt, execinfo.range_begin, execinfo.range_end);

            break;

        case EXECODE_ERASE:
            szmaxpkt = buf_stdvec.size();
            if (szmaxpkt < 1) {
                flg_skip = true;
                break;
            }
            assert ((ssize_t)szhdr == ds3hdr_mac_to_nbs(NULL, 0, &machdr));
            if (NULL == pinfo) {
                assert (szmaxpkt > 0);
                assert (szmaxpkt >= szhdr);
                execinfo.range_begin = rand () % (szmaxpkt - szhdr) + szhdr;
                execinfo.range_end = rand () % (szmaxpkt - szhdr); // the size
                if (execinfo.range_begin + execinfo.range_end > (ssize_t)szmaxpkt) {
                    execinfo.range_end = szmaxpkt;
                } else {
                    execinfo.range_end = execinfo.range_begin + execinfo.range_end;
                }
            }
            assert (execinfo.range_begin < (ssize_t)szmaxpkt);
            assert (execinfo.range_end <= (ssize_t)szmaxpkt);

            if ((execinfo.range_begin < (ssize_t)szhdr) || (execinfo.range_end - execinfo.range_begin + szhdr > buf_stdvec.size())) {
                // we don't want to delete the first header
                flg_skip = true;
                std::cerr << std::dec << "[" << i << "] SKIP erase"
                    << " tobegin " << execinfo.range_begin
                    << " toend "   << execinfo.range_end
                    << std::endl;
                break;
            }

            std::cerr << std::dec << "[" << i << "] erase"
                << " tobegin " << execinfo.range_begin
                << " toend "   << execinfo.range_end
                << std::endl;

            std::cerr << std::dec << "    /*" << i << "*/{ "
                << ds3_test_exec2desc(execinfo.exec) << ", "
                << execinfo.sq          << " /* sq */, "
                << execinfo.maxsz       << " /* maxsz */, "
                << execinfo.range_begin << " /* range_begin */, "
                << execinfo.range_end   << " /* range_end */, "
                << execinfo.pos_self    << " /* pos_self */, "
                << "}," << std::endl;

            buf_stdvec.erase (buf_stdvec.begin() + execinfo.range_begin, buf_stdvec.begin() + execinfo.range_end);
            // bool ds3_packet_buffer_gpkt_t::erase (size_t begin_self, size_t end_self);
            buf_gpkt.erase(execinfo.range_begin, execinfo.range_end);
            break;

        default:
            flg_skip = true;
            break;
        }
        // compare
        if ((ssize_t)buf_stdvec.size() != buf_gpkt.size()) {
            std::cerr << std::dec << "Error: at round " << i << ", the size of buffer stdvec=" << buf_stdvec.size() << " != gpkt=" << buf_gpkt.size() << std::endl;
            flg_error = true;
        }
        for (j = 0; j < buf_stdvec.size(); j ++) {
            if (buf_stdvec[j] != buf_gpkt[j]) {
                std::cerr << std::dec << "Error: at round " << i
                    << ", szbuf=" << buf_stdvec.size()
                    << ", the content of buffer stdvec[" << std::dec << j << "]=0x" << std::hex << std::setfill('0') << std::setw(2) << (int)(buf_stdvec[j])
                    << " != gpkt[" << std::dec << j << "]=0x" << std::hex << std::setfill('0') << std::setw(2) << (int)(buf_gpkt[j])
                    << std::endl;
                flg_error = true;
                break;
            }
        }
            std::cerr << "dump of stdvec, sz=" << std::dec << buf_stdvec.size() << ":" << std::endl;
            std::cerr << "  ";
            for (j = 0; j < buf_stdvec.size(); j ++) {
                std::cerr  << " " << std::hex << std::setfill('0') << std::setw(2) << (int)(buf_stdvec[j]);
                if ((j + 1) % 16 == 0) std::cerr << std::endl << "  ";
            }
            std::cerr << std::endl;
        if (flg_error) {
            std::cerr << "dump of gpkt, sz=" << std::dec << buf_gpkt.size() << ":" << std::endl;
            std::cerr << "  ";
            for (j = 0; (ssize_t)j < buf_gpkt.size(); j ++) {
                std::cerr  << " " << std::hex << std::setfill('0') << std::setw(2) << (int)(buf_gpkt[j]);
                if ((j + 1) % 16 == 0) std::cerr << std::endl << "  ";
            }
            std::cerr << std::endl;
        }
        if (flg_error) {
            break;
        }
        if (! flg_skip) {
            i ++;
        }
        flg_skip = false;
    }

    // test extract
    // ds3_packet_generic_t ds3_packet_buffer_gpkt_t::extract_gpkt (size_t pos);

    // test gpkt
    ds3packet_testmac_t pkt_gpkt;

    // clean
    std::vector<ds3packet_nbsmac_t *>::iterator itpkt;
    for (itpkt = pktlist.begin(); itpkt != pktlist.end(); itpkt ++) {
        delete (*itpkt);
    }
    if (flg_error) {
        return -1;
    }
    return 0;
}

#define NUMARRAY(v) (sizeof(v)/sizeof(v[0]))

static int
test_ns2ccf_fix1 (void)
{
    ds3_test_exec_info_t testcase1[] = {
        { EXECODE_INSERT_FROM, 0 /* sq */,  1 /* maxsz */, 0 /* range_begin */, 5 /* range_end */, 0 /* pos_self */, },
        { EXECODE_INSERT_FROM, 1 /* sq */,  MAX_SIZE_PKT /* maxsz */, 5 /* range_begin */, 7 /* range_end */, 1 /* pos_self */, },
    };

    return test_ns2ccf_gp (testcase1, NUMARRAY(testcase1));
}

static int
test_ns2ccf_fix2 (void)
{
    ds3_test_exec_info_t testcase1[] = {
        /*0*/{ EXECODE_INSERT_FROM, 0 /* sq */, 0 /* maxsz */, 0 /* range_begin */, 4 /* range_end */, 0 /* pos_self */, },
    };

    return test_ns2ccf_gp (testcase1, NUMARRAY(testcase1));
}

static int
test_ns2ccf_fix3 (void)
{
    ds3_test_exec_info_t testcase1[] = {
        { EXECODE_INSERT_FROM, 0 /* sq */, 152 /* maxsz */, 0 /* range_begin */, 156 /* range_end */, 0 /* pos_self */, },
        { EXECODE_INSERT_FROM, 1 /* sq */, 219 /* maxsz */, 35 /* range_begin */, 52 /* range_end */, 50 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 26 /* range_begin */, 166 /* range_end */, -1 /* pos_self */, },
    };

    return test_ns2ccf_gp (testcase1, NUMARRAY(testcase1));
}


static int
test_ns2ccf_fix4 (void)
{
    ds3_test_exec_info_t testcase1[] = {
        { EXECODE_INSERT_FROM, 0 /* sq */, 203 /* maxsz */, 0 /* range_begin */, 207 /* range_end */, 0 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 152 /* range_begin */, 207 /* range_end */, -1 /* pos_self */, },
        { EXECODE_INSERT_FROM, 1 /* sq */, 200 /* maxsz */, 63 /* range_begin */, 176 /* range_end */, 124 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 77 /* range_begin */, 265 /* range_end */, -1 /* pos_self */, },
        { EXECODE_INSERT_FROM, 2 /* sq */, 216 /* maxsz */, 95 /* range_begin */, 220 /* range_end */, 11 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 73 /* range_begin */, 202 /* range_end */, -1 /* pos_self */, },
        { EXECODE_INSERT_FROM, 3 /* sq */, 131 /* maxsz */, 20 /* range_begin */, 66 /* range_end */, 34 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 61 /* range_begin */, 119 /* range_end */, -1 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 52 /* range_begin */, 61 /* range_end */, -1 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 17 /* range_begin */, 52 /* range_end */, -1 /* pos_self */, },
        { EXECODE_INSERT_FROM, 4 /* sq */, 45 /* maxsz */, 47 /* range_begin */, 49 /* range_end */, 12 /* pos_self */, },
        { EXECODE_INSERT_FROM, 5 /* sq */, 201 /* maxsz */, 152 /* range_begin */, 205 /* range_end */, 4 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 49 /* range_begin */, 72 /* range_end */, -1 /* pos_self */, },
        { EXECODE_INSERT_FROM, 6 /* sq */, 5 /* maxsz */, 7 /* range_begin */, 9 /* range_end */, 24 /* pos_self */, },
        { EXECODE_INSERT_FROM, 7 /* sq */, 10 /* maxsz */, 13 /* range_begin */, 14 /* range_end */, 7 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 51 /* range_begin */, 52 /* range_end */, -1 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 45 /* range_begin */, 51 /* range_end */, -1 /* pos_self */, },
        { EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 13 /* range_begin */, 22 /* range_end */, -1 /* pos_self */, },
    };
    return test_ns2ccf_gp (testcase1, NUMARRAY(testcase1));
}

static int
test_ns2ccf_fix5 (void)
{
    ds3_test_exec_info_t testcase1[] = {
        /*0*/{ EXECODE_INSERT_FROM, 0 /* sq */, 109 /* maxsz */, 0 /* range_begin */, 113 /* range_end */, 0 /* pos_self */, },
        /*1*/{ EXECODE_INSERT_FROM, 1 /* sq */, 227 /* maxsz */, 213 /* range_begin */, 231 /* range_end */, 14 /* pos_self */, },
        /*2*/{ EXECODE_INSERT_FROM, 2 /* sq */, 164 /* maxsz */, 138 /* range_begin */, 168 /* range_end */, 124 /* pos_self */, },
        /*3*/{ EXECODE_INSERT_FROM, 3 /* sq */, 134 /* maxsz */, 46 /* range_begin */, 138 /* range_end */, 100 /* pos_self */, },
        /*4*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 50 /* range_begin */, 131 /* range_end */, -1 /* pos_self */, },
        /*5*/{ EXECODE_INSERT_FROM, 4 /* sq */, 49 /* maxsz */, 39 /* range_begin */, 49 /* range_end */, 140 /* pos_self */, },
        /*6*/{ EXECODE_INSERT_FROM, 5 /* sq */, 2 /* maxsz */, 3 /* range_begin */, 5 /* range_end */, 42 /* pos_self */, },
        /*7*/{ EXECODE_INSERT_FROM, 6 /* sq */, 88 /* maxsz */, 63 /* range_begin */, 92 /* range_end */, 133 /* pos_self */, },
        /*8*/{ EXECODE_INSERT_FROM, 7 /* sq */, 111 /* maxsz */, 62 /* range_begin */, 99 /* range_end */, 60 /* pos_self */, },
        /*9*/{ EXECODE_INSERT_FROM, 8 /* sq */, 29 /* maxsz */, 6 /* range_begin */, 15 /* range_end */, 101 /* pos_self */, },
        /*10*/{ EXECODE_INSERT_FROM, 9 /* sq */, 119 /* maxsz */, 72 /* range_begin */, 123 /* range_end */, 184 /* pos_self */, },
        /*11*/{ EXECODE_INSERT_FROM, 10 /* sq */, 113 /* maxsz */, 49 /* range_begin */, 117 /* range_end */, 79 /* pos_self */, },
        /*12*/{ EXECODE_INSERT_FROM, 11 /* sq */, 16 /* maxsz */, 3 /* range_begin */, 9 /* range_end */, 361 /* pos_self */, },
        /*13*/{ EXECODE_INSERT_FROM, 12 /* sq */, 18 /* maxsz */, 0 /* range_begin */, 1 /* range_end */, 232 /* pos_self */, },
        /*14*/{ EXECODE_INSERT_FROM, 13 /* sq */, 177 /* maxsz */, 79 /* range_begin */, 157 /* range_end */, 32 /* pos_self */, },
        /*15*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 198 /* range_begin */, 463 /* range_end */, -1 /* pos_self */, },
        /*16*/{ EXECODE_INSERT_FROM, 14 /* sq */, 60 /* maxsz */, 29 /* range_begin */, 64 /* range_end */, 15 /* pos_self */, },
        /*17*/{ EXECODE_INSERT_FROM, 15 /* sq */, 19 /* maxsz */, 6 /* range_begin */, 11 /* range_end */, 202 /* pos_self */, },
        /*18*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 193 /* range_begin */, 238 /* range_end */, -1 /* pos_self */, },
        /*19*/{ EXECODE_INSERT_FROM, 16 /* sq */, 134 /* maxsz */, 7 /* range_begin */, 129 /* range_end */, 122 /* pos_self */, },
        /*20*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 146 /* range_begin */, 315 /* range_end */, -1 /* pos_self */, },
        /*21*/{ EXECODE_INSERT_FROM, 17 /* sq */, 165 /* maxsz */, 133 /* range_begin */, 169 /* range_end */, 74 /* pos_self */, },
        /*22*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 85 /* range_begin */, 182 /* range_end */, -1 /* pos_self */, },
        /*23*/{ EXECODE_INSERT_FROM, 18 /* sq */, 12 /* maxsz */, 5 /* range_begin */, 12 /* range_end */, 14 /* pos_self */, },
        /*24*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 69 /* range_begin */, 92 /* range_end */, -1 /* pos_self */, },
        /*25*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 22 /* range_begin */, 39 /* range_end */, -1 /* pos_self */, },
        /*26*/{ EXECODE_INSERT_FROM, 19 /* sq */, 132 /* maxsz */, 38 /* range_begin */, 136 /* range_end */, 10 /* pos_self */, },
        /*27*/{ EXECODE_INSERT_FROM, 20 /* sq */, 188 /* maxsz */, 67 /* range_begin */, 139 /* range_end */, 119 /* pos_self */, },
        /*28*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 13 /* range_begin */, 161 /* range_end */, -1 /* pos_self */, },
        /*29*/{ EXECODE_INSERT_FROM, 21 /* sq */, 233 /* maxsz */, 82 /* range_begin */, 237 /* range_end */, 20 /* pos_self */, },
        /*30*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 107 /* range_begin */, 229 /* range_end */, -1 /* pos_self */, },
        /*31*/{ EXECODE_INSERT_FROM, 22 /* sq */, 191 /* maxsz */, 188 /* range_begin */, 195 /* range_end */, 91 /* pos_self */, },
        /*32*/{ EXECODE_INSERT_FROM, 23 /* sq */, 10 /* maxsz */, 9 /* range_begin */, 14 /* range_end */, 102 /* pos_self */, },
        /*33*/{ EXECODE_INSERT_FROM, 24 /* sq */, 43 /* maxsz */, 17 /* range_begin */, 29 /* range_end */, 109 /* pos_self */, },
        /*34*/{ EXECODE_INSERT_FROM, 25 /* sq */, 133 /* maxsz */, 15 /* range_begin */, 137 /* range_end */, 103 /* pos_self */, },
        /*35*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 168 /* range_begin */, 253 /* range_end */, -1 /* pos_self */, },
        /*36*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 138 /* range_begin */, 150 /* range_end */, -1 /* pos_self */, },
        /*37*/{ EXECODE_INSERT_FROM, 26 /* sq */, 179 /* maxsz */, 172 /* range_begin */, 183 /* range_end */, 150 /* pos_self */, },
        /*38*/{ EXECODE_INSERT_FROM, 27 /* sq */, 192 /* maxsz */, 104 /* range_begin */, 175 /* range_end */, 88 /* pos_self */, },
        /*39*/{ EXECODE_INSERT_FROM, 28 /* sq */, 60 /* maxsz */, 17 /* range_begin */, 52 /* range_end */, 199 /* pos_self */, },
        /*40*/{ EXECODE_INSERT_FROM, 29 /* sq */, 128 /* maxsz */, 49 /* range_begin */, 132 /* range_end */, 88 /* pos_self */, },
        /*41*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 28 /* range_begin */, 267 /* range_end */, -1 /* pos_self */, },
        /*42*/{ EXECODE_INSERT_FROM, 30 /* sq */, 103 /* maxsz */, 80 /* range_begin */, 93 /* range_end */, 32 /* pos_self */, },
        /*43*/{ EXECODE_INSERT_FROM, 31 /* sq */, 85 /* maxsz */, 6 /* range_begin */, 62 /* range_end */, 30 /* pos_self */, },
        /*44*/{ EXECODE_INSERT_FROM, 32 /* sq */, 51 /* maxsz */, 15 /* range_begin */, 54 /* range_end */, 176 /* pos_self */, },
        /*45*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 141 /* range_begin */, 209 /* range_end */, -1 /* pos_self */, },
        /*46*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 19 /* range_begin */, 132 /* range_end */, -1 /* pos_self */, },
        /*47*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 25 /* range_begin */, 44 /* range_end */, -1 /* pos_self */, },
        /*48*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 17 /* range_begin */, 25 /* range_end */, -1 /* pos_self */, },
        /*49*/{ EXECODE_INSERT_FROM, 33 /* sq */, 19 /* maxsz */, 0 /* range_begin */, 20 /* range_end */, 14 /* pos_self */, },
        /*50*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 18 /* range_begin */, 30 /* range_end */, -1 /* pos_self */, },
        /*51*/{ EXECODE_INSERT_FROM, 34 /* sq */, 117 /* maxsz */, 82 /* range_begin */, 110 /* range_end */, 4 /* pos_self */, },
        /*52*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 47 /* range_begin */, 53 /* range_end */, -1 /* pos_self */, },
        /*53*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 35 /* range_begin */, 47 /* range_end */, -1 /* pos_self */, },
        /*54*/{ EXECODE_INSERT_FROM, 35 /* sq */, 53 /* maxsz */, 28 /* range_begin */, 57 /* range_end */, 19 /* pos_self */, },
        /*55*/{ EXECODE_INSERT_FROM, 36 /* sq */, 195 /* maxsz */, 40 /* range_begin */, 157 /* range_end */, 17 /* pos_self */, },
        /*56*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 47 /* range_begin */, 71 /* range_end */, -1 /* pos_self */, },
        /*57*/{ EXECODE_INSERT_FROM, 37 /* sq */, 130 /* maxsz */, 16 /* range_begin */, 75 /* range_end */, 85 /* pos_self */, },
        /*58*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 168 /* range_begin */, 216 /* range_end */, -1 /* pos_self */, },
        /*59*/{ EXECODE_INSERT_FROM, 38 /* sq */, 177 /* maxsz */, 138 /* range_begin */, 181 /* range_end */, 55 /* pos_self */, },
        /*60*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 13 /* range_begin */, 99 /* range_end */, -1 /* pos_self */, },
        /*61*/{ EXECODE_INSERT_FROM, 39 /* sq */, 56 /* maxsz */, 19 /* range_begin */, 60 /* range_end */, 34 /* pos_self */, },
        /*62*/{ EXECODE_INSERT_FROM, 40 /* sq */, 90 /* maxsz */, 73 /* range_begin */, 94 /* range_end */, 113 /* pos_self */, },
        /*63*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 24 /* range_begin */, 93 /* range_end */, -1 /* pos_self */, },
        /*64*/{ EXECODE_INSERT_FROM, 41 /* sq */, 147 /* maxsz */, 22 /* range_begin */, 93 /* range_end */, 55 /* pos_self */, },
        /*65*/{ EXECODE_ERASE, -1 /* sq */, -1 /* maxsz */, 106 /* range_begin */, 189 /* range_end */, -1 /* pos_self */, },
        /*66*/{ EXECODE_INSERT_FROM, 42 /* sq */, 23 /* maxsz */, 1 /* range_begin */, 1 /* range_end */, 19 /* pos_self */, },
    };
    return test_ns2ccf_gp (testcase1, NUMARRAY(testcase1));
}

int
test_ns2ccf_random (void)
{
    srand(time(NULL));
    size_t nump = rand () % 100;
    return test_ns2ccf_gp (NULL, nump);
}

int
test_ns2ccf (void)
{
    /*REQUIRE (0 == test_ns2ccf_fix1());
    REQUIRE (0 == test_ns2ccf_fix2());
    REQUIRE (0 == test_ns2ccf_fix3());*/
    //REQUIRE (0 == test_ns2ccf_fix4());
    //REQUIRE (0 == test_ns2ccf_fix2());
    REQUIRE (0 == test_ns2ccf_random());
    return 0;
}

#endif
