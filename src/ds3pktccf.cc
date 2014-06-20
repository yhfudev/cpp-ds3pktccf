/**
 * @file    ds3pktccf.cc
 * @brief   process DOCSIS CCF header
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-12
 * @copyright Yunhui Fu (2014)
 * @bug No known bugs.
 */

#include <stdio.h>
#include <netinet/in.h> // htons()

#include "ds3pktccf.h"

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

    if (szbuf == 0) {
        /* return size of header*/
        return 8;
    }
    if (NULL == nbsbuf) {
        return -1;
    }
    if (szbuf < 8) {
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

    return 8;
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

    if (NULL == nbsbuf) {
        return -1;
    }
    if (szbuf < 8) {
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

    return 8;
}

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
ds3packet_t::get_pkt_bytes (size_t pos, std::vector<uint8_t> & nbsbuf, size_t szbuf)
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
ds3packet_t::get_pkt_bytes (size_t pos, uint8_t *nbsbuf, size_t szbuf)
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
        if (newoff >= this->buffer.size()) {
            return szcur;
        }
        szcpy = szbuf - szcur;
        if (szcpy + newoff > this->buffer.size()) {
            szcpy = this->buffer.size() - newoff;
        }
        std::copy (this->buffer.begin() + newoff, this->buffer.begin() + newoff + szcpy, nbsbuf + szcur);
        szcur = szbuf;
    }
    return szcur;
}

/**
 * @brief set the content of the packet, not include the header
 * @param nbsbuf : the buffer contains the content
 * @param szbuf : the size of the data in the buffer
 * @return 0 on success, < 0 on error
 */
int
ds3packet_t::set_content (uint8_t *nbsbuf, size_t szbuf)
{
    assert (NULL != nbsbuf);
    assert (szbuf > 0);
    if (szbuf < 1) {
        this->buffer.resize(0);
        return 0;
    }
    if (NULL == nbsbuf) {
        return -1;
    }
    this->buffer.resize(0);
    //this->buffer.reserve(szbuf);
    this->buffer.insert(this->buffer.begin(), nbsbuf, nbsbuf + szbuf);
    return 0;
}

ssize_t
ds3packet_ccf_t::to_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    if (0 == szbuf) {
        return (ds3hdr_ccf_to_nbs(NULL, 0, &(this->ccfhdr)) + this->buffer.size());
    }
    if (NULL == nbsbuf) {
        return -1;
    }
    size_t sz;
    sz = ds3hdr_ccf_to_nbs(nbsbuf, szbuf, &(this->ccfhdr));
    if (sz > 0) {
        memmove (nbsbuf + sz, &(this->buffer)[0], this->buffer.size());
        sz += this->buffer.size();
    }
    return sz;
}

ssize_t
ds3packet_ccf_t::from_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    int ret;
    ds3hdr_ccf_t tmp;
    ret = ds3hdr_ccf_from_nbs (nbsbuf, szbuf, &tmp);
    if (ret < 0) {
        return 0;
    }
    memmove (&(this->ccfhdr), &tmp, sizeof (tmp));

    this->buffer.reserve(szbuf - ret);
    memmove (&(this->buffer)[0], nbsbuf + ret, szbuf - ret);
    this->buffer.resize(szbuf - ret);
    return szbuf;
}

/**
 * @brief dump the content
 * @return N/A
 */
void
ds3packet_t::dump_content (void)
{
    std::cout << "   content: " ;// << std::endl;
    std::vector<uint8_t>::iterator itb = this->get_content_ref().begin();
    std::vector<uint8_t>::iterator ite = this->get_content_ref().end();
    for (; itb != ite; itb ++ ) {
        printf (" %02X", *itb);
    }
    std::cout << std::endl;
}

void
ds3packet_ccf_t::dump (void)
{
    ds3hdr_ccf_t & ccfhdr = this->get_header();
    std::cout << "CCF pkt"
        //<< ", type: "       << typeid(p).name()
        << ", hdr.sequence=" << ccfhdr.sequence
        << ", cnt.sz="      << this->get_content_ref().size() << "/" << this->get_size()
        << ", hdr.pfi="     << ccfhdr.pfi
        << ", hdr.offmac="  << ccfhdr.offmac
        << ", hdr.sc="      << ccfhdr.sc
        << ", hdr.request=" << ccfhdr.request
        << ", hdr.hcs="     << ccfhdr.hcs
        << std::endl;
    this->dump_content ();
}

/**
 * @brief check if (i < j)
 * @param i : the left hand of the value
 * @param j : the right hand of the value
 * @return true if (i < j), false otherwise
 */
static bool
compare_ccfpktp (ds3packet_ccf_t * i, ds3packet_ccf_t * j)
{
    return (i->get_header().sequence < j->get_header().sequence);
}

/**
 * @brief push a segment received for unpacking, try to extract DOCSIS MAC packet(s) from CCF segments
 *
 * @param p : [in] a CCF segment be pushed into the queue
 *
 * @return the number of segments to be sent, >0 on success, < 0 on error
 *
 * push a segment received for unpacking, try to extract DOCSIS MAC packet(s) from CCF segments
 *
 * In this function, we use the segment header's field offmax as the pointer to process MAC header,
 * we also use it as a pointer to indicate if the data before the 1st MAC hdr is processed or not;
 * there's another data pointer ds3packet_t.pos_next to indicate the next MAC hdr.
 */
int
ds3_ccf_unpack_t::process_packet (ds3packet_t *p)
{
    std::cout << "ds3_ccf_unpack_t::process_packet got packet:" << std::endl;
    p->dump();

    ds3packet_ccf_t* pktin = dynamic_cast<ds3packet_ccf_t *>(p);
    assert (NULL != pktin);

    // add p to sortedPackets
    std::vector<ds3packet_ccf_t *>::iterator itins = pkglst.begin();
    if (NULL != p) {
        // get the piggyback request
        ds3hdr_ccf_t & ccfhdr = pktin->get_header();
        if (ccfhdr.request > 0) {
            this->signify_piggyback (ccfhdr.sc, ccfhdr.request);
        }

        pktin->set_procpos(0);
        std::vector<ds3packet_ccf_t *>::iterator itup = pkglst.begin();
        itup = std::upper_bound (pkglst.begin(), pkglst.end(), pktin, compare_ccfpktp);
        itins = pkglst.insert(itup, pktin);
    }

    // find the left most and right most positions which have continual sequence number
    std::vector<ds3packet_ccf_t *>::iterator itprev = itins;
    std::vector<ds3packet_ccf_t *>::iterator itleft = itins;
    itprev = itleft;
    for (; itleft != pkglst.begin(); itleft --) {
        if ((*itleft)->get_header().sequence + 1 < (*itprev)->get_header().sequence) {
            break;
        }
        itprev = itleft;
    }
    std::vector<ds3packet_ccf_t *>::iterator itright = itins;
    itprev = itright;
    for (; itright != pkglst.end(); itright ++) {
        if ((*itprev)->get_header().sequence + 1 < (*itright)->get_header().sequence) {
            break;
        }
        itprev = itright;
    }
    // debug:
    //assert (itright == pkglst.end());

    size_t off;
    std::vector<uint8_t> hdrbuf; /* buffer for MAC header and/or content */
    std::vector<ds3packet_ccf_t *>::iterator it1st = itleft; /* record the first segment position that is the begin of MAC header */

#define USE_DS3_MICRO 0

/** set the ccfhdr.offmac to 0 to indicate that the data before the first MAC hdr is processed */
#define DS3PKGLST_SET_PROCESSED_OFFMAC(itleft) \
        if ( (*itleft)->get_procpos() < (*itleft)->get_header().offmac ) { \
            (*itleft)->set_procpos ((*itleft)->get_header().offmac); \
        } \
        (*itleft)->get_header().offmac = 0;

/** remove the processed/corrupted segments */
#define DS3PKGLST_REMOVE() \
        if (it1st != itleft) { \
            if ((*it1st)->get_header().offmac > 0) { \
                it1st ++; \
            } \
            if (it1st != itleft) { \
                pkglst.erase (it1st, itleft); \
            } \
        } \
        it1st = itleft; \
        /* we also set the ccfhdr.offmac to 0 to indicate that the data before the first MAC hdr is processed */ \
        DS3PKGLST_SET_PROCESSED_OFFMAC (itleft)

#define DS3PKGLST_PROCESS_BODY() \
        /* get the length of MAC */ \
        if (hdrbuf.size() >= (size_t)(szmhdr + machdr.length)) { \
            assert (hdrbuf.size() >= (size_t)(szmhdr + machdr.length)); \
            size_t szbk = (hdrbuf.size() - (size_t)(szmhdr + machdr.length)); \
            size_t szrest = (cntbufref.end() - (cntbufref.begin() + off)); \
            size_t szadd = szrest - szbk; \
            /* resize the buffer according to machdr.length */ \
            std::cout << "the size of data in the buffer not belonging to the packet: " << szbk << std::endl; \
            std::cout << "the size of data were read in current segment: " << szrest << std::endl; \
            std::cout << "set the offset from " << off << " to " << (off + szadd) << std::endl; \
            (*itleft)->set_procpos (off + szadd); \
            hdrbuf.resize((size_t)(szmhdr + machdr.length)); \
            /* extract the packet */ \
            this->signify_packet (hdrbuf); \
            hdrbuf.resize(0); \
            /* remove the processed segments */ \
            DS3PKGLST_REMOVE (); \
        } else { \
            /* no enough content data bytes */ \
            /* wait for next one? */ \
        }

    // find the first segment contains the MAC header
    for (; itleft != itright; ) {

        if ((*itleft)->get_header().pfi == 1) {
            // find the next unprocessed MAC header
            assert ((*itleft)->get_header().pfi == 1);
            off = (*itleft)->get_header().offmac;
            if (off > (*itleft)->get_procpos()) {
                (*itleft)->set_procpos(off);
            }
        }
        off = (*itleft)->get_procpos();
        std::vector<uint8_t> & cntbufref = (*itleft)->get_content_ref();
        if (off >= cntbufref.size()) {
            // this segment is processed from the start of offmac to the end
            assert (off == (*itleft)->get_content_ref().size());
            if ((*itleft)->get_header().offmac < 1) {
                // there's no data before the first MAC header, or no MAC header
                assert ((*itleft)->get_header().offmac == 0);

                size_t off1 = (itleft - pkglst.begin());
                size_t off2 = (itright - pkglst.begin());
                assert (off2 >= off1);
                pkglst.erase(itleft);
                if (pkglst.size() < 1) {
                    assert (pkglst.begin() == pkglst.end());
                    itleft = itright = pkglst.end();
                } else {
                    itleft = pkglst.begin() + (off1 - 1);
                    itright = pkglst.begin() + (off2 - 1);
                }

            } else {
                itleft ++;
            }

        } else {
            // check if we can get MAC header
            ssize_t szmhdr = -1;
            ds3hdr_mac_t machdr;
            memset (&machdr, 0, sizeof (machdr));
            bool flg_data_left = false; /* use the left data of offmac to fill hdrbuf */
            bool flg_data_right = false;  /* use the right data of procpos to fill hdrbuf */

            if (hdrbuf.size() <= 0) {
                assert (hdrbuf.size() == 0);
                // this is the first segment of the packet
                assert ((*itleft)->get_header().pfi == 1);
                it1st = itleft;
                hdrbuf.insert (hdrbuf.end(), cntbufref.begin() + off, cntbufref.end());
                flg_data_right = true;
                // try to find a new MAC header
                szmhdr = ds3hdr_mac_from_nbs (&hdrbuf[0], hdrbuf.size(), &machdr);
                if (szmhdr <= 0) {
                    // no enough header bytes
                    // wait for next one?
                    itleft ++;
                    continue;
                } else {
                    // get the header successfully
                    if (hdrbuf.size() < (size_t)(szmhdr + machdr.length)) {
                        itleft ++;
                        continue;
                    }
                }

            } else {
                bool flg_corrupted = false;
                bool flg_continue = false;
                // there's incomplete MAC header in previous segment
                if ((*itleft)->get_header().pfi == 1) {
                    // this should be the last segment of the packet
                    // attach the content from the buffer to hdrbuf by size of offmac
                    hdrbuf.insert (hdrbuf.end(), cntbufref.begin(), cntbufref.begin() + (*itleft)->get_header().offmac);
                    flg_data_left = true;
                } else {
                    // this whole segment is a part of the packet
                    assert ((*itleft)->get_procpos() == 0);
                    assert (off == (*itleft)->get_procpos());
                    hdrbuf.insert (hdrbuf.end(), cntbufref.begin() + off, cntbufref.end());
                    flg_data_right = true;
                }
                szmhdr = ds3hdr_mac_from_nbs (&hdrbuf[0], hdrbuf.size(), &machdr);
                if (szmhdr <= 0) {
                    if ((*itleft)->get_header().pfi == 1) {
                        // Error: impossible to here! or there's error in the packet
                        flg_corrupted = true;
                    } else {
                        // no enough header bytes
                        // wait for next one?
                        flg_continue = true;
                    }
                } else {
                    // get the header successfully
                    if (hdrbuf.size() < (size_t)(szmhdr + machdr.length)) {
                        szmhdr = 0; // reset the header so that it continue
                        if ((*itleft)->get_header().pfi == 1) {
                            // Error: corrupted packet
                            flg_corrupted = true;
                        } else {
                            // no enough header bytes
                            // wait for next one?
                        }
                        // no enough content bytes
                        // wait for next one?
                        flg_continue = true;
                    } else {
                        // data is enough to extract,
                        // the data will be throw away after extraction in spit of success of fail
                        assert (szmhdr > 0);
                    }
                }
                if (flg_corrupted) {
                    // skip this packet and continue
                    hdrbuf.resize(0);
#if USE_DS3_MICRO // 2
                    DS3PKGLST_REMOVE_FAIL ();
#else // 2
                    if (it1st != itleft) {
                        if ((*it1st)->get_header().offmac > 0) {
                            it1st ++;
                        }
                        if (it1st != itleft) {
                            std::vector<ds3packet_ccf_t *>::iterator ittmp = it1st;
                            for (; ittmp != itleft; ittmp ++) {
                                this->drop_packet( *ittmp );
                            }

                            std::cout << "pkg end-begin=" << (pkglst.end() - pkglst.begin()) << std::endl;
                            size_t off1 = (itleft - pkglst.begin());
                            size_t off2 = (itright - pkglst.begin());
                            assert (off2 >= off1);
                            pkglst.erase (it1st, itleft);
                            if (pkglst.size() < 1) {
                                assert (pkglst.begin() == pkglst.end());
                                itleft = itright = pkglst.end();
                            } else {
                                itleft = pkglst.begin() + (off1 - 1);
                                itright = pkglst.begin() + (off2 - 1);
                            }
                        }
                    }
                    it1st = itleft;
#if USE_DS3_MICRO // 3
                    DS3PKGLST_SET_PROCESSED_OFFMAC (itleft);
#else // 3
                    /* we also set the ccfhdr.offmac to 0 to indicate that the data before the first MAC hdr is processed */
                    if ( (*itleft)->get_procpos() < (*itleft)->get_header().offmac ) {
                        (*itleft)->set_procpos ((*itleft)->get_header().offmac);
                    }
                    if (flg_data_left) {
                        (*itleft)->get_header().offmac = 0;
                    }
#endif // 3
#endif // 2
                }
                if (flg_continue) {
                    itleft ++;
                    continue;
                }
            }
            if (szmhdr > 0) {
                // got a mac header
#if USE_DS3_MICRO // 1
                DS3PKGLST_PROCESS_BODY();
#else // 1
                if (hdrbuf.size() >= (size_t)(szmhdr + machdr.length)) {
                    assert (hdrbuf.size() >= (size_t)(szmhdr + machdr.length));
                    if (flg_data_left) {
                        // do nothing
                    }
                    if (flg_data_right) {
                        size_t szbk = (hdrbuf.size() - (size_t)(szmhdr + machdr.length));
                        size_t szrest = (cntbufref.end() - (cntbufref.begin() + off));
                        size_t szadd = szrest - szbk;
                        /* resize the buffer according to machdr.length */
                        std::cout << "the size of data in the buffer not belonging to the packet: " << szbk << std::endl;
                        std::cout << "the size of data were read in current segment: " << szrest << std::endl;
                        std::cout << "set the next offset from " << off << " to " << (off + szadd) << std::endl;
                        (*itleft)->set_procpos (off + szadd);
                    }

                    hdrbuf.resize((size_t)(szmhdr + machdr.length));
                    /* extract the packet */
                    this->signify_packet (hdrbuf);
                    hdrbuf.resize(0);
                    /* remove the processed segments */
#if USE_DS3_MICRO // 2
                    DS3PKGLST_REMOVE_OK ();
#else // 2
                    if (it1st != itleft) {
                        if ((*it1st)->get_header().offmac > 0) {
                            it1st ++;
                        }
                        if (it1st != itleft) {

                            std::vector<ds3packet_ccf_t *>::iterator ittmp = it1st;
                            for (; ittmp != itleft; ittmp ++) {
                                this->recycle_packet( *ittmp );
                            }

                            std::cout << "pkg end-begin=" << (pkglst.end() - pkglst.begin()) << std::endl;
                            size_t off1 = (itleft - pkglst.begin());
                            size_t off2 = (itright - pkglst.begin());
                            assert (off2 >= off1);
                            pkglst.erase (it1st, itleft);
                            if (pkglst.size() < 1) {
                                assert (pkglst.begin() == pkglst.end());
                                itleft = itright = pkglst.end();
                            } else {
                                itleft = pkglst.begin() + (off1 - 1);
                                itright = pkglst.begin() + (off2 - 1);
                            }
                        }
                    }
                    it1st = itleft;
#if USE_DS3_MICRO // 3
                    DS3PKGLST_SET_PROCESSED_OFFMAC (itleft);
#else // 3
                    /* we also set the ccfhdr.offmac to 0 to indicate that the data before the first MAC hdr is processed */
                    if ( (*itleft)->get_procpos() < (*itleft)->get_header().offmac ) {
                        (*itleft)->set_procpos ((*itleft)->get_header().offmac);
                    }
                    if (flg_data_left) {
                        (*itleft)->get_header().offmac = 0;
                    }
#endif // 3
#endif // 2
                } else {
                    /* no enough content data bytes */
                    /* wait for next one? */
                    assert (0); /* we have already process the exceptions */
                }
#endif // 1
            } /* if (szmhdr > 0) */
        } /* if (off >= cntbufref.size()) */
    } /* itleft loop */

    // TODO: remove the timeout packets in the sortedPackets

    return 0;
}

/**
 * @brief push a new packet to the sending list, and send segment(s) according current grants
 *
 * @param p : [in] the packet
 *
 * @return the number of segments to be sent, >0 on success, < 0 on error
 *
 * push a new packet to the sending list, and send segment(s) according current grants.
 *
 * It's assumed that the grants are exist for the packets in the list,
 * so the size of grants are always larger than(>=) the ``requested packet'' size.
 */
int
ds3_ccf_pack_t::process_packet (ds3packet_t *p)
{
    if (NULL != p) {
        std::cout << "ds3_ccf_pack_t::process_packet got packet:" << std::endl;
        p->dump();

        p->set_procpos(0); /* reset the processed position to 0 */
        this->pktlst.push_back (p);
    }
    size_t numSeg = 0;
    size_t szMax = 0;
    size_t szCur = 0;
    size_t szNext = 0;
    ds3hdr_ccf_t ccfhdr;
    std::vector<uint8_t> buffer;
    // remove the timeout grants
    std::vector<ds3_grant_t>::iterator itg;
    double tmcur = this->current_time();
    for (itg = this->grantlst.begin(); itg != this->grantlst.end(); itg ++) {
        if (tmcur > itg->get_time()) {
            /* invalid grant, delete it */
            continue;
        }
        if (pktlst.size() < 1) {
            // empty
            break;
        }
        szMax = itg->get_size();
        assert (szMax > (size_t)ds3hdr_ccf_to_nbs(NULL, 0, NULL));
        szCur = ds3hdr_ccf_to_nbs(NULL, 0, NULL);
        buffer.resize (0);
        memset (&ccfhdr, 0, sizeof(ccfhdr));
        for (; szCur < szMax;) {
            assert (pktlst.size() > 0);
            assert (NULL != pktlst[0]);
            assert (pktlst[0]->get_size() > 0);
            if (0 == pktlst[0]->get_procpos()) {
                /* It's the beginning of the packet */
                if (0 == ccfhdr.pfi) {
                    ccfhdr.pfi = 1;
                    assert (szCur >= (size_t)ds3hdr_ccf_to_nbs(NULL, 0, NULL));
                    ccfhdr.offmac = (szCur - ds3hdr_ccf_to_nbs(NULL, 0, NULL));
                }
            }
            assert (pktlst[0]->get_size() > pktlst[0]->get_procpos());
            szNext = pktlst[0]->get_size() - pktlst[0]->get_procpos();
            if (szCur + szNext > szMax) {
                szNext = szMax - szCur;
            }
            /* fill the buffer */
            ssize_t ret1 = pktlst[0]->get_pkt_bytes (pktlst[0]->get_procpos(), buffer, szNext);
            assert ((size_t)ret1 == szNext);
            szCur += szNext;
            pktlst[0]->set_procpos (pktlst[0]->get_procpos() + szNext);
            if (pktlst[0]->get_procpos() >= pktlst[0]->get_size()) {
                /* all of the contents of the front packet(pktlst[0]) in the queue are in sending buffer */
                this->recycle_packet (pktlst[0]); // delete pktlst[0];
                pktlst.erase (pktlst.begin());
                if (pktlst.size() < 1) {
                    break;
                }
            }
        }
        if (szCur > (size_t)ds3hdr_ccf_to_nbs(NULL, 0, NULL)) {
            /* It's time to send the segment, and continue to next grant */
            if (this->piggyback_inc > 0) {
                ccfhdr.request = this->piggyback_inc / DS3_MULTIPLIER_REQUEST;
                this->piggyback_inc = 0;
            }
            ccfhdr.sequence = this->get_next_sequence();
            /* set the CCF header */
            ds3packet_ccf_t * ccfpkt = new ds3packet_ccf_t();
            assert (NULL != ccfpkt);
            ccfpkt->set_header(&ccfhdr);
            ccfpkt->set_content(buffer);
            /* send the CCF segment */
            this->start_sndpkt_timer(itg->get_time(), DS3EVT_TMRPKT, ccfpkt, itg->get_channel_id() );
            numSeg ++;
        }
    }
    if (itg != this->grantlst.begin()) {
        /* delete invalid or used grants */
        this->grantlst.erase (this->grantlst.begin(), itg);
    }

    return numSeg;
}

/**
 * @brief add grants and piggyback request
 *
 * @param grants : [in] the grants list
 * @param piggyback : [in] the piggyback request value
 *
 * @return 0 on success, < 0 on error
 *
 * add grants and piggyback request
 *
 * This function will also process the MAC packets for all of the added grants
 */
int
ds3_ccf_pack_t::add_grants (std::vector<ds3_grant_t> & grants, size_t piggyback)
{
    piggyback_inc += piggyback;
    grantlst.insert (grantlst.end(), grants.begin(), grants.end());
    std::sort (grantlst.begin(), grantlst.end());

    process_packet (NULL);
    return 0;
}
