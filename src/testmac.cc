/**
 * @file    testmac.cc
 * @brief   fake mac for testing
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-19
 * @copyright Yunhui Fu (2014)
 */

#include <netinet/in.h> // htons()

#include "testmac.h"

#if 0
/**
 * @brief The DOCSIS MAC header structure
 */
typedef struct _ds3hdr_mac_t {
    uint16_t sequence; /**< The sequence # of the MAC packet */
    uint16_t length; /**< The length of the data in the MAC packet */
} ds3hdr_mac_t;

ssize_t ds3hdr_mac_to_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_mac_t * refhdr);
ssize_t ds3hdr_mac_from_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_mac_t * rethdr);
#endif

/**
 * @brief convert struct to network byte sequence
 *
 * @param nbsbuf : [in,out] the buffer pointer contains the network byte sequence of the data, to be filled by this function
 * @param szbuf : [in] the size  of the buffer passed in
 * @param refhdr : [in] the pointer of the structure
 *
 * @return the byte size of the header processed, >0 on success, < 0 on error
 *
 * convert struct to network byte sequence
 */
ssize_t
ds3hdr_mac_to_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_mac_t * refhdr)
{
    ssize_t ret = sizeof(uint16_t) * 2;
    uint16_t v16 = 0;
    uint8_t * p = nbsbuf;

    if (szbuf == 0) {
        /* return size of header*/
        return (ret);
    }
    if (NULL == nbsbuf) {
        return -1;
    }
    if ((ssize_t)szbuf < ret) {
        return -1;
    }
    if (NULL == refhdr) {
        return -1;
    }

    v16 = htons (refhdr->sequence);
    memmove (p, &v16, sizeof (v16));
    p += sizeof(v16);

    v16 = htons (refhdr->length);
    memmove (p, &v16, sizeof (v16));
    p += sizeof(v16);

    return (ret);
}

/**
 * @brief convert network byte sequence to structure
 *
 * @param nbsbuf : [in] the buffer pointer contains the network byte sequence of the data
 * @param szbuf : [in] the size  of the buffer passed in
 * @param rethdr : [out] the pointer of the structure to be filled by this function
 *
 * @return the byte size of the header processed, >0 on success, < 0 on error
 *
 * convert network byte sequence to structure
 */
ssize_t
ds3hdr_mac_from_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_mac_t * rethdr)
{
    ssize_t ret = sizeof(uint16_t) * 2;
    uint8_t * p = nbsbuf;

    if (szbuf == 0) {
        return ret;
    }
    if (NULL == nbsbuf) {
        return -1;
    }
    if ((ssize_t)szbuf < ret) {
        return -1;
    }
    if (NULL == rethdr) {
        return -1;
    }
    memset (rethdr, 0, sizeof (*rethdr));

    rethdr->sequence = ntohs (*((uint16_t *)p));
    p = p + 2;

    rethdr->length = ntohs (*((uint16_t *)p));
    p = p + 2;

    return (ret);
}

ssize_t
ds3_packet_buffer_nbsmac_t::block_size_at (size_t pos)
{
    // size of sub-block (including header+content)
    ds3hdr_mac_t machdr;
    if (pos >= (this->buffer).size()) {
        return -1;
    }
    memset (&machdr, 0, sizeof(machdr));
    assert ((this->buffer).size() > pos);
    ssize_t szhdr = ds3hdr_mac_from_nbs (&(this->buffer[pos]), (this->buffer).size() - pos, &machdr);
    if (szhdr < 0) {
        return -1;
    }
    return ( szhdr + (ssize_t)(machdr.length) );
}

#if CCFDEBUG
void
ds3packet_nbsmac_t::dump (void)
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
#endif

ssize_t
ds3packet_nbsmac_t::to_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    ssize_t szret = 0;
    size_t szcur = 0;
    this->get_header();

    if (0 == szbuf) {
        return ds3hdr_mac_to_nbs (NULL, 0, &(this->machdr)) + this->get_content_ref().size();
    }
    szret = ds3hdr_mac_to_nbs (nbsbuf, szbuf, &(this->machdr));
    if (szret < 0) {
        return -1;
    }
    if (szret + this->get_content_ref().size() > (ssize_t)szbuf) {
        return -1;
    }
    szcur += szret;

    //std::copy (this->buffer.begin(), this->buffer.end(), nbsbuf + szcur);
    //memmove (nbsbuf + szcur, &(this->buffer[0]), this->buffer.end() - this->buffer.begin());
    this->get_content_ref().to_nbs (nbsbuf + szcur, this->get_content_ref().size());
    szcur += (this->get_content_ref().size());

    return szcur;
}

ssize_t
ds3packet_nbsmac_t::from_nbs (uint8_t *nbsbuf, size_t szbuf)
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
    //memmove (&(this->machdr), &tmphdr, sizeof (tmphdr));
    this->set_header (&tmphdr);
    // the content
    this->get_content_ref().from_nbs (nbsbuf + szcur, tmphdr.length);

    szcur += tmphdr.length;
    return szcur;
}

ssize_t
ds3packet_nbsmac_t::from_nbs (ds3_packet_buffer_t *peer, size_t pos_peer)
{
    ssize_t szret = 0;
    size_t szcur = 0;

    szret = ds3hdr_mac_from_nbs (NULL, 0, &(this->machdr));
    assert (szret > 0);
    if ((ssize_t)(pos_peer + szret) > peer->size()) {
        return -1;
    }
    // the ``MAC header''
    ds3hdr_mac_t tmphdr;
    std::vector<uint8_t> buffer1;
#if 0
    peer->append_to (buffer1);
#else
    buffer1.resize(szret);
    for (int i; i < szret; i ++) {
        buffer1[i] = peer->at(pos_peer + i);
    }
#endif // 1
    size_t szbuf = buffer1.size();
    szret = ds3hdr_mac_from_nbs (&(buffer1[0]), szbuf, &tmphdr);
    if (szret < 0) {
        return -1;
    }
    szcur += szret;
    if ((ssize_t)(szcur + tmphdr.length + pos_peer) > peer->size()) {
        // no enough data
        return -1;
    }
    memmove (&(this->machdr), &tmphdr, sizeof (tmphdr));
    // the content
    //buffer.resize(tmphdr.length);
    //std::copy (nbsbuf + szcur, nbsbuf + szcur + tmphdr.length, this->buffer.begin());
    this->get_content_ref().resize(0);
    this->get_content_ref().insert (this->get_content_ref().end(), peer, peer->begin() + pos_peer + szcur, peer->begin() + (pos_peer + szcur + tmphdr.length));

    szcur += tmphdr.length;
    return szcur;
}

//bool operator < (const ds3packet_nbsmac_t & lhs, const ds3packet_nbsmac_t & rhs);
bool
ds3packet_nbsmac_t::operator == (const ds3packet_nbsmac_t & rhs) const
{
    if (this->machdr.length != rhs.machdr.length) {
#if DEBUG
std::cout << "[pktnbs.equ?] hdr.length: lhs(self)=" << this->machdr.length << " != rhs=" << rhs.machdr.length << std::endl;
#endif // DEBUG
        return false;
    }
    if (this->machdr.sequence != rhs.machdr.sequence) {
#if DEBUG
std::cout << "[pktnbs.equ?] hdr.sequence: lhs(self)=" << this->machdr.sequence << " != rhs=" << rhs.machdr.sequence << std::endl;
#endif // DEBUG
        return false;
    }
    if (this->buffer.size() != rhs.buffer.size()) {
#if DEBUG
std::cout << "[pktnbs.equ?] buffer.size: lhs(self)=" << this->buffer.size() << " != rhs=" << rhs.buffer.size() << std::endl;
#endif // DEBUG
        return false;
    }
    for (ssize_t i = 0; i < this->buffer.size(); i ++) {
        if (this->buffer[i] != rhs.buffer[i]) {
#if DEBUG
std::cout << "[pktnbs.equ?] buffer.at(" << i << "): lhs(self)=" << this->buffer[i] << " != rhs=" << rhs.buffer[i] << std::endl;
#endif // DEBUG
            return false;
        }
    }
    return true;
}

#if 0
/**
 * @brief get the raw data bytes(network byte sequence) of the packet
 *
 * @param pos : [in] the start position of the byte sequence
 * @param nbsbuf : [in,out] the buffer to be filled
 * @param szbuf : [in] the size requested to be filled
 *
 * @return the size of data copied to buffer, >0 on success, < 0 on error
 *
 * get the raw data bytes(network byte sequence) of the packet
 */
ssize_t
ds3packet_nbsmac_t::copy_to (size_t pos, std::vector<uint8_t> & nbsbuf, size_t szbuf)
{
    ssize_t ret;
    size_t szorig;
    szorig = nbsbuf.size();
    nbsbuf.resize (nbsbuf.size() + szbuf);
    ret = get_pkt_bytes (pos, &nbsbuf[szorig], szbuf);
    if (ret > 0) {
        nbsbuf.resize(szorig + ret);
    } else {
        nbsbuf.resize(szorig);
    }
    return ret;
}

/**
 * @brief get the raw data bytes(network byte sequence) of the packet
 *
 * @param pos : [in] the start position of the byte sequence
 * @param nbsbuf : [in,out] the buffer to be filled
 * @param szbuf : [in] the size requested to be filled
 *
 * @return the size of data copied to buffer, >0 on success, < 0 on error
 *
 * get the raw data bytes(network byte sequence) of the packet
 */
ssize_t
ds3packet_nbsmac_t::copy_to (size_t pos, uint8_t *nbsbuf, size_t szbuf)
{
    size_t szcpy = 0;
    size_t szcur = 0; /* the buffer used */
    size_t szhdr = this->hdr_to_nbs (NULL, 0);

    if (pos < szhdr) {
        /* part of content is the header */
        if (szhdr + szcur <= szbuf) {
            /* there's enough buffer from the user */
            hdr_to_nbs (nbsbuf + szcur, szbuf - szcur);
            if (pos > 0) {
                assert (szhdr > pos);
                memmove (nbsbuf + szcur, nbsbuf + szcur + pos, szhdr - pos);
            }
            szcur += (szhdr - pos);
        } else {
            // create a new buffer
            std::vector<uint8_t> buffer1;
            buffer1.resize(szhdr * 2);
            hdr_to_nbs (&buffer1[0], buffer1.size());
            buffer1.resize(szhdr);
            assert (szhdr >= pos);
            assert (szhdr > szbuf);
            szcpy = szhdr - pos;
            if (szcpy + szcur > szbuf) {
                szcpy = szbuf - szcur;
            }
            assert (szcpy + pos < buffer1.size());
            std::copy (buffer1.begin() + pos, buffer1.begin() + pos + szcpy, nbsbuf + szcur);
            szcur += szcpy;
        }
    }
    if (szcur < szbuf) {
        size_t newoff = 0;
        if (pos > szhdr) {
            newoff = pos - szhdr;
        }
        if ((ssize_t)newoff >= this->buffer.size()) {
            return szcur;
        }
        szcpy = szbuf - szcur;
        if ((ssize_t)(szcpy + newoff) > this->buffer.size()) {
            szcpy = this->buffer.size() - newoff;
        }
        std::copy (this->buffer.begin() + newoff, this->buffer.begin() + newoff + szcpy, nbsbuf + szcur);
        szcur = szbuf;
    }
    return szcur;
}
#endif

/**
 * This function only support std::vector<uint8_t> buffer!
 */
ds3_packet_buffer_t *
ds3packet_nbsmac_t::insert_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self)
{
#if 0
    DS3_DYNCST_CHKRET_DS3PKT_BUFFER(ds3_packet_buffer_nbs_t, arg_peer);
#else
#ifdef ds3_real_type
#undef ds3_real_type
#endif
#define ds3_real_type ds3_packet_buffer_nbsmac_t
    ds3_real_type *peer = NULL;
    bool flg_peer_is_new = false;
    if (NULL == (arg_peer)) {
        /* create a new buf, and copy itself from [begin_self, end_self], return the new buf */
        (arg_peer) = peer = new ds3_real_type ();
        flg_peer_is_new = true;
    } else {
        peer = dynamic_cast<ds3_real_type *>(arg_peer);
        if (NULL == peer) {
            if (NULL != (arg_peer)->get_buffer()) {
                /* it's a base class, and it stored the content from other ns2 content */
                peer = dynamic_cast<ds3_real_type *>((arg_peer)->get_buffer());
            }
        }
        if (NULL == peer) {
            /* create a new one, and try to append to the current arg_peer */
            ds3_real_type p;
            assert (NULL != (arg_peer));
            (arg_peer)->insert(0, &p, 0, 0);

            if (NULL != (arg_peer)->get_buffer()) {
                /* it's a base class, and it stored the content from other ns2 content */
                peer = dynamic_cast<ds3_real_type *>((arg_peer)->get_buffer());
            }
        }
    }
    if (NULL == peer) {
        assert (0);
        return NULL;
    }
    if ((ssize_t)pos_peer > peer->size()) {
        if (flg_peer_is_new) { free (peer); }
        return NULL;
    }
    if (begin_self >= this->size()) {
        /* do nothing */
        return (arg_peer);
    }
    if (end_self > this->size()) {
        end_self = this->size();
    }
#endif

    assert (NULL != peer);
    if (begin_self >= end_self) {
        return arg_peer;
    }
    size_t szcpy = 0;
    size_t szcur = 0; /* the buffer used */
    size_t szhdr = this->hdr_to_nbs (NULL, 0);

    size_t pos = begin_self;
    size_t szbuf = end_self - begin_self;

    if (pos < szhdr) {
        /* part of content is the header */
        // create a new buffer
        std::vector<uint8_t> buffer1;
        buffer1.resize(szhdr * 2);
        hdr_to_nbs (&buffer1[0], buffer1.size());
        buffer1.resize(szhdr);
        assert (szhdr >= pos);
        szcpy = szhdr - pos;
        if (szcpy + szcur > szbuf) {
            szcpy = szbuf - szcur;
        }
        if (szcpy + pos > buffer1.size()) {
            szcpy = buffer1.size() - pos;
        }
        assert (szcpy + szcur <= szbuf);
        //std::copy (buffer1.begin() + pos, buffer1.begin() + pos + szcpy, nbsbuf + szcur);
        assert (pos < buffer1.size());
        assert (pos + szcpy <= buffer1.size());
        std::vector<uint8_t>::iterator it1b = buffer1.begin() + pos;
        std::vector<uint8_t>::iterator it1e = buffer1.begin() + pos + szcpy;
        peer->append (it1b, it1e);
        szcur += szcpy;
    }
    if (szcur < szbuf) {
        size_t newoff = 0;
        if (pos > szhdr) {
            newoff = pos - szhdr;
        }
        ds3_packet_buffer_t & cntbufref = this->get_content_ref();
        if ((ssize_t)newoff >= cntbufref.size()) {
            return arg_peer;
        }
        szcpy = szbuf - szcur;
        if ((ssize_t)(szcpy + newoff) > cntbufref.size()) {
            szcpy = cntbufref.size() - newoff;
        }
        //std::copy (cntbufref.begin() + newoff, cntbufref.begin() + newoff + szcpy, nbsbuf + szcur);
        peer->insert (peer->end(), &cntbufref, cntbufref.begin() + newoff, cntbufref.begin() + (newoff + szcpy));
        szcur = szbuf;
    }
    return arg_peer;
}

#if CCFDEBUG
#include <stdio.h>

#ifndef REQUIRE
#define REQUIRE assert
#endif

int
test_machdr (void)
{
    ds3hdr_mac_t machdr, machdr2, *ph;
    uint8_t buffer[sizeof (machdr) * 2];

    ph = &machdr;
    memset (ph, 0, sizeof(*ph));
    ph->length = 530;
    ph->sequence = 17;

    ph = &machdr2;
    memset (ph, 0, sizeof(*ph));

    ds3hdr_mac_to_nbs (buffer, sizeof (buffer), &machdr);
    ds3hdr_mac_from_nbs (buffer, sizeof (buffer), &machdr2);
#define MYCHK1(name1) REQUIRE (machdr.name1 == machdr2.name1)
    MYCHK1(length);
    MYCHK1(sequence);

    if (0 != memcmp (&machdr, &machdr2, sizeof(machdr))) {
        printf ("[%s()] Error in machdr2!\n", __func__);
        return -1;
    }
    printf ("[%s()] Passed !\n", __func__);
    return 0;
#undef  MYCHK1
}
#endif
