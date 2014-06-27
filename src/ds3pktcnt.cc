/**
 * @file    ds3pktcnt.cc
 * @brief   ds3 packet content
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-20
 * @copyright Yunhui Fu (2014)
 */

#include <stdio.h>
#include <netinet/in.h> // htons()

#include "ds3pktcnt.h"

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
ds3hdr_ccf_to_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_ccf_t * refhdr)
{
    /* DOCSIS 3.1: 6.2.1.2
     * "Within the MAC layer, when numeric quantities are represented by more than one octet (i.e., 16-bit and 32-bit
values), the octet containing the most-significant bits is the first transmitted on the wire. This is sometimes called
byte-big-endian order."
     * So,
     *   we convert the data to network byte sequence (big-endian), and the left most is the high bit(use "<< #" to shift in C),
     */
    uint16_t v16 = 0;
    uint8_t * p = nbsbuf;
    ssize_t ret = sizeof(uint16_t) * 4;

    if (szbuf == 0) {
        /* return size of header*/
        return ret;
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

    v16 = refhdr->offmac;
    if (refhdr->pfi) {
        v16 |= 0x8000; // (0x01 << 15);
    }
    if (refhdr->r) {
        v16 |= 0x4000; // (0x01 << 14);
    }
    v16 = htons (v16);
    memmove (p, &v16, sizeof (v16));
    p += sizeof(v16);

    v16 = (refhdr->sequence << 3) | (refhdr->sc & 0x07);
    v16 = htons (v16);
    memmove (p, &v16, sizeof (v16));
    p += sizeof(v16);

    v16 = htons (refhdr->request);
    memmove (p, &v16, sizeof (v16));
    p += sizeof(v16);

    v16 = htons (refhdr->hcs);
    memmove (p, &v16, sizeof (v16));
    p += sizeof(v16);

    return ret;
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
ds3hdr_ccf_from_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_ccf_t * rethdr)
{
    uint16_t v16 = 0;
    uint8_t * p = nbsbuf;
    ssize_t ret = sizeof(uint16_t) * 4;

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

    v16 = ntohs (*((uint16_t *)p));
    if (v16 & 0x8000) {
        rethdr->pfi = 1;
    }
    if (v16 & 0x4000) {
        rethdr->r = 1;
    }
    rethdr->offmac = v16 & 0x3FFF;
    p = p + 2;

    v16 = ntohs (*((uint16_t *)p));
    rethdr->sequence = (v16 >> 3);
    rethdr->sc = v16 & 0x07;
    p = p + 2;

    rethdr->request = ntohs (*((uint16_t *)p));
    p = p + 2;

    rethdr->hcs = ntohs (*((uint16_t *)p));

    return ret;
}

/**
 * @brief copy the content from peer.
 *
 * the base class don't need to know the details of the child class,
 * it only need to store the pointer of the sub-class, and pass it to the memeber function again once needed.
 */
ssize_t
ds3_packet_buffer_t::copy (size_t pos_self, ds3_packet_buffer_t *peer, size_t begin_peer, size_t end_peer)
{
    assert (NULL != peer);
    ds3_packet_buffer_t * new_content;
    new_content = peer->copy_to(pos_self, this->contents_buffer, begin_peer, end_peer);
    if (NULL == new_content) {
        return -1;
    }
    this->contents_buffer = new_content;
    return (end_peer - begin_peer);
}

ssize_t
ds3_packet_buffer_t::insert (size_t pos_self, ds3_packet_buffer_t *peer, size_t begin_peer, size_t end_peer)
{
    assert (NULL != peer);
    ds3_packet_buffer_t * new_content;
    new_content = peer->insert_to(pos_self, this->contents_buffer, begin_peer, end_peer);
    if (NULL == new_content) {
        return -1;
    }
    this->contents_buffer = new_content;
    return (end_peer - begin_peer);
}

ssize_t ds3_packet_buffer_nbs_t::size(void) const { return this->buffer.size(); }

ssize_t
ds3_packet_buffer_nbs_t::append (std::vector<uint8_t>::iterator & begin1, std::vector<uint8_t>::iterator & end1)
{
    this->buffer.insert(this->buffer.end(), begin1, end1);
    return (end1 - begin1);
}

ssize_t
ds3_packet_buffer_nbs_t::append (uint8_t *buf, size_t sz)
{
    this->buffer.insert(this->buffer.end(), buf, buf + sz);
    return (sz);
}

ds3_packet_buffer_nbs_t::ds3_packet_buffer_nbs_t(ds3_packet_buffer_t *arg_peer, size_t begin, size_t end)
{
    ds3_packet_buffer_nbs_t * peer = dynamic_cast<ds3_packet_buffer_nbs_t *> (arg_peer);
    assert (NULL != peer);
    if (end < begin) {
        return;
    }
    if (begin >= (peer->buffer).size()) {
        return;
    }
    if (end > (peer->buffer).size()) {
        end = (peer->buffer).size();
    }
    this->buffer.resize (0);
    //std::copy (peer->buffer.begin() + begin, peer->buffer.begin() + end, this->buffer.begin());
    this->buffer.insert (this->buffer.begin(), peer->buffer.begin() + begin, peer->buffer.begin() + end);
}

ssize_t
ds3_packet_buffer_nbs_t::to_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    assert (szbuf >= this->buffer.size());
    if (szbuf > this->buffer.size()) {
        szbuf = this->buffer.size();
    }
    std::copy (this->buffer.begin(), this->buffer.begin() + szbuf, nbsbuf);
    return szbuf;
}

ssize_t
ds3_packet_buffer_nbs_t::from_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    this->buffer.resize(szbuf);
    std::copy (nbsbuf, nbsbuf + szbuf, this->buffer.begin());
    return szbuf;
}

ds3_packet_buffer_t *
ds3_packet_buffer_nbs_t::insert_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self)
{
#if 0
    DS3_DYNCST_CHKRET_CONTENT_POINTER(ds3_packet_buffer_nbs_t, arg_peer);
#else
#ifdef ds3_real_type
#undef ds3_real_type
#endif
#define ds3_real_type ds3_packet_buffer_nbs_t
    if (NULL == arg_peer) {
        /* create a new buf, and copy itself from [begin_self, end_self], return the new buf */
        ds3_packet_buffer_t * newpkt = this->create (this, begin_self, end_self);
        return newpkt;
    }
    ds3_real_type *peer = dynamic_cast<ds3_real_type *>(arg_peer);
    if (NULL == peer) {
        assert (0);
        return NULL;
    }
    if ((ssize_t)pos_peer > peer->size()) {
        return NULL;
    }
    if ((ssize_t)begin_self >= this->size()) {
        /* do nothing */
        return arg_peer;
    }
    if ((ssize_t)end_self > this->size()) {
        end_self = this->size();
    }
#endif
    assert (NULL != peer);
    // add the content between [begin_self, end_self) to peer
    // peer has to be the same typs as this
    peer->buffer.insert(peer->buffer.begin() + pos_peer, buffer.begin() + begin_self, buffer.begin() + end_self);
    return arg_peer;
}

ds3_packet_buffer_t *
ds3_packet_buffer_nbs_t::copy_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self)
{
    DS3_DYNCST_CHKRET_CONTENT_POINTER(ds3_packet_buffer_nbs_t, arg_peer);
    assert (NULL != peer);
    // add the content between [begin_self, end_self) to peer
    // peer has to be the same typs as this
    peer->buffer.insert(peer->buffer.begin() + pos_peer, buffer.begin() + begin_self, buffer.begin() + end_self);
    std::copy(this->buffer.begin() + begin_self, this->buffer.begin() + end_self, peer->buffer.begin() + pos_peer);
    return arg_peer;
}

#if CCFDEBUG
void
ds3_packet_buffer_nbs_t::dump (void)
{
    std::cout << "   content: " ;// << std::endl;
    std::vector<uint8_t>::iterator itb = this->buffer.begin();
    std::vector<uint8_t>::iterator ite = this->buffer.end();
    for (; itb != ite; itb ++ ) {
        printf (" %02X", *itb);
    }
    std::cout << std::endl;
}
#endif


#if CCFDEBUG

#ifndef REQUIRE
#define REQUIRE(a) if (! (a)) { assert(a); return -1; }
#endif

int
test_ccfhdr (void)
{
    ds3hdr_ccf_t ccfhdr, ccfhdr2, *ph;
    uint8_t buffer[sizeof (ccfhdr) * 2];

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
#undef  MYCHK1
}

#ifndef REQUIRE
#define REQUIRE assert
#endif

int
test_pktcnt (void)
{
    //ds3_packet_buffer_ns2_t *cnt;
    uint8_t buf1[132];
    uint8_t buf2[32];
    memset (&buf1, 0x11, sizeof(buf1));
    memset (&buf2, 0x22, sizeof(buf2));
    ds3_packet_buffer_nbs_t cntnbs;
    ds3_packet_buffer_t cnt1;

    cntnbs.append(buf1, sizeof(buf1));
    cntnbs.append(buf2, sizeof(buf2));
    cnt1.insert(0, &cntnbs, 0, cntnbs.size());
    std::cout << "cnt.size=" << cnt1.size() << std::endl;
    REQUIRE (cnt1.size() == sizeof(buf1) + sizeof(buf2));
    std::cout << "cnt1.dump():" << std::endl;
    cnt1.dump();
    return 0;
}
#endif

