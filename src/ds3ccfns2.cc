/**
 * @file    ds3ccfns2.cc
 * @brief   CCF class for NS2 DOCSIS module
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-19
 * @copyright Yunhui Fu (2014)
 */

#include <iostream>
#include "ds3ccfns2.h"

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
        pi.pos = this->pktlist[i].pos + (pos_cur - szcur);
        pi.sz = this->pktlist[i].sz;
        pi.sz -= (pi.pos - this->pktlist[i].pos);
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
                this->pktlist[i].sz = (pi.pos + pi.sz) - this->pktlist[i].pos;
                this->pktlist[i].pos = pi.pos + pi.sz;
                std::vector<ds3pktbufns2_info_t>::iterator it = this->pktlist.begin() + i;
                this->pktlist.insert(it, pi2);
                i ++;
            }
            assert (szcur + this->pktlist[i].sz > pos_cur + pi.sz);
        }
        szcur += this->pktlist[i].sz;
        pos_cur += pi.sz;
    }

    return true;
}

// i = the index of insecting position
// szcur = the size of data before this one
bool
ds3_packet_buffer_gpkt_t::insert_gpkt_idx (size_t i, size_t szcur, size_t pos_self, ds3_packet_generic_t pkt, size_t begin_peer, size_t end_peer)
{
    ds3pktbufns2_info_t pi;
    pi.pkt = pkt;
    pi.pos = begin_peer;
    assert (end_peer > begin_peer);
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
    } else {
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
            } else {
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
            }
        }
    }
    assert (0);
    return false;
}

bool
ds3_packet_buffer_gpkt_t::insert_gpkt (size_t pos_self, ds3_packet_generic_t pkt, size_t begin_peer, size_t end_peer)
{
    size_t szcur = 0;
    size_t i = 0;

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

#define EXECODE_INSERT 0x00
#define EXECODE_COPY   0x01
#define EXECODE_ERASE  0x02
#define EXECODE_LAST   EXECODE_ERASE
#define EXECODE_SIZE   (EXECODE_LAST + 1)

int
test_ns2ccf (void)
{
    int execode;
    std::vector<uint8_t> buf_stdvec;
    ds3_packet_buffer_test_t buf_gpkt;
    ds3_packet_buffer_nbsmac_t buf_nbs;

    ds3packet_nbsmac_t * pktnew = NULL;
    std::vector<ds3packet_nbsmac_t *> pktlist;

    size_t szmaxpkt = 238;
    uint16_t sequence = 0;
    std::vector<uint8_t> buf_fillcontent;
    ds3hdr_mac_t machdr;
    uint8_t macbuf[10];
    size_t szhdr = 0;
    size_t i;
    for (i = 0; i < szmaxpkt; i ++) {
        buf_fillcontent.push_back(0x11 + i);
    }

    std::vector<uint8_t>::iterator itb;
    std::vector<uint8_t>::iterator ite;
    ds3_packet_buffer_nbs_t nbscnt;
    std::vector<uint8_t> buf_tmp;

    //srand(0); // srand (time(NULL));

    size_t pos_self;
    size_t pos_begin;
    size_t pos_end;
    // test ds3_packet_buffer_gpkt_t
    execode = rand () % EXECODE_SIZE;
    switch (execode) {
    case EXECODE_INSERT:
        // insert a new packet
        //  1. insert raw packet to std::vector<uint8_t>
        //  2. insert a new nbsmac packet to nbsmac
        //  3. insert a new nbsmac packet to gpkt
        //  4. compare all of the packet with std::vector<uint8_t>
        //     make sure they are equal of contents (except the header of first packet).
        memset (&machdr, 0, sizeof(machdr));
        machdr.sequence = sequence; sequence ++;
        machdr.length = rand () % (buf_fillcontent.size()) + 1;

        assert (machdr.length <= buf_fillcontent.size());
        szhdr = ds3hdr_mac_to_nbs(NULL, 0, &machdr);
        assert (sizeof(macbuf) >= szhdr);
        szhdr = ds3hdr_mac_to_nbs(macbuf, sizeof(macbuf), &machdr);

        buf_tmp.resize(0);
        std::copy (macbuf, macbuf + szhdr, buf_tmp.end());
        std::copy (buf_fillcontent.begin(), buf_fillcontent.begin() + machdr.length, buf_tmp.end());
        pos_begin = rand () % (buf_tmp.size());
        pos_end = rand () % (buf_tmp.size() + 1);
        assert (pos_begin < buf_tmp.size());
        assert (pos_end <= buf_tmp.size());

        /**
         * make sure that the inserted position is not in the mac header area of the first packet
         * since we need to handle the packets overlay (for testing ds3packet_nbsmac_t)
         */
        assert ((ssize_t)szhdr == ds3hdr_mac_to_nbs(NULL, 0, &machdr));
        pos_self = rand () % (buf_stdvec.size() + 1);
        if (buf_stdvec.size() > 0) {
            assert (buf_stdvec.size() > szhdr);
            pos_self = rand () % (buf_stdvec.size() - szhdr + 1) + szhdr;
        }

        std::cerr << "insert sq " << machdr.sequence
            << " sz " << machdr.length
            << " range (" << pos_begin << "," << pos_end << ")"
            << " at " << pos_self
            << std::endl;

        // vector buffer
        buf_stdvec.insert (buf_stdvec.begin() + pos_self, buf_tmp.begin() + pos_begin, buf_tmp.begin() + pos_end);

        pktnew = new ds3packet_nbsmac_t();
        itb = buf_fillcontent.begin();
        ite = buf_fillcontent.begin() + machdr.length;
        nbscnt.append(itb, ite);
        pktnew->set_content (&nbscnt);
        nbscnt.resize(0);
        pktnew->sethdr_sequence(machdr.sequence);
        pktlist.push_back(pktnew); // backup the pointer

        // ds3packet
        //ssize_t ds3_packet_buffer_t::insert (size_t pos_self, ds3_packet_buffer_t *peer, size_t begin_peer, size_t end_peer);
        //buf_nbs.insert (pos_self, peer1, begin1, end1);

        // generic packet
        //bool ds3_packet_buffer_gpkt_t::insert_gpkt (size_t pos_self, ds3_packet_generic_t peer_pkt, size_t begin_peer, size_t end_peer);
        assert (pos_begin < pktnew->size());
        assert (pos_end <= pktnew->size());
        buf_gpkt.insert_gpkt(pos_self, pktnew, pos_begin, pos_end);

        // compare

        break;

    case EXECODE_COPY:
        // ssize_t ds3_packet_buffer_t::copy (size_t pos_self, ds3_packet_buffer_t *peer, size_t begin_peer, size_t end_peer);
        break;

    case EXECODE_ERASE:
        // bool ds3_packet_buffer_gpkt_t::erase (size_t begin_self, size_t end_self);
        break;
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
    return -1;
}
#endif
