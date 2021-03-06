/**
 * @file    ds3pktccf.cc
 * @brief   process DOCSIS CCF header
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-12
 * @copyright Yunhui Fu (2014)
 */

#include <stdio.h>

#include "ds3pktccf.h"

#define USE_DS3_LATESNDPIG 1

const char *
ds3_event2desc (ds3event_t e)
{
#define MYCASE(v) case v: return #v
    switch (e) {
        MYCASE(DS3EVT_MAP);
        MYCASE(DS3EVT_PKT);
        MYCASE(DS3EVT_TMRPKT);
        MYCASE(DS3EVT_TMRREQ);
    }
    return "UNKNOWN";
#undef MYCASE
}

#if 0
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
#endif

ssize_t
ds3packet_ccf_t::to_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    if (0 == szbuf) {
        return (ds3hdr_ccf_to_nbs(NULL, 0, &(this->ccfhdr)) + this->buffer.size());
    }
    if (NULL == nbsbuf) {
        return -1;
    }
    assert ( (ssize_t)szbuf >= (ds3hdr_ccf_to_nbs(NULL, 0, &(this->ccfhdr)) + this->buffer.size()) );
    size_t sz;
    sz = ds3hdr_ccf_to_nbs(nbsbuf, szbuf, &(this->ccfhdr));
    if (sz > 0) {
        assert (szbuf > sz);

        //memmove (nbsbuf + sz, &(this->buffer)[0], this->buffer.size());
        this->buffer.to_nbs (nbsbuf + sz, szbuf - sz);

        sz += this->buffer.size();
    }
    return sz;
}

ssize_t
ds3packet_ccf_t::from_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    ssize_t ret;
    ds3hdr_ccf_t tmp;
    ret = ds3hdr_ccf_from_nbs (nbsbuf, szbuf, &tmp);
    if (ret < 0) {
        return 0;
    }
    memmove (&(this->ccfhdr), &tmp, sizeof (tmp));

    //this->buffer.resize(szbuf - ret); memmove (&(this->buffer)[0], nbsbuf + ret, szbuf - ret);
    assert ((ssize_t)szbuf >= ret);
    this->buffer.from_nbs (nbsbuf + ret, szbuf - ret);

    return szbuf;
}

#if CCFDEBUG
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

uint8_t &
ds3packet_ccf_t::at(size_t i)
{
    assert ((ssize_t)sizeof (this->ccfhdrbuf) >= ds3hdr_ccf_to_nbs (NULL, 0, &(this->ccfhdr)));
    if ((ssize_t)i < ds3hdr_ccf_to_nbs (NULL, 0, &(this->ccfhdr))) {
        this->hdr_to_nbs (this->ccfhdrbuf, sizeof(this->ccfhdrbuf));
        return this->ccfhdrbuf[i];
    }
    assert ((ssize_t)i >= ds3hdr_ccf_to_nbs (NULL, 0, &(this->ccfhdr)));
    return (this->get_content_ref().at(i - ds3hdr_ccf_to_nbs (NULL, 0, &(this->ccfhdr))));
}

uint8_t &
ds3packet_t::at(size_t i)
{
    static uint8_t t = -1;
    DS3_WRONGFUNC_RETVAL(t);
}
#endif

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
 * @brief find the next node of a continual sequence in a loop list
 *
 * @param pkglst: the list
 * @param itins: the current node
 *
 * @return the first node, end() on error
 */
std::vector<ds3packet_ccf_t *>::iterator
ds3pktlstccf_next (std::vector<ds3packet_ccf_t *> & pkglst, std::vector<ds3packet_ccf_t *>::iterator & itins)
{
    std::vector<ds3packet_ccf_t *>::iterator itnext = itins;
    if (itins == pkglst.end()) {
        return pkglst.end();
    }
    itnext ++;
    if (itnext == pkglst.end()) {
        itnext = pkglst.begin ();
    }
    if (itnext == itins) {
        return pkglst.end();
    }
    return itnext;
}

std::vector<ds3packet_ccf_t *>::iterator
ds3pktlstccf_next_pivot (std::vector<ds3packet_ccf_t *> & pkglst
    , std::vector<ds3packet_ccf_t *>::iterator & itins
    , std::vector<ds3packet_ccf_t *>::iterator & itp)
{
    std::vector<ds3packet_ccf_t *>::iterator itnext = ds3pktlstccf_next(pkglst, itins);
    if (itnext == itp) {
        return pkglst.end();
    }
    return itnext;
}

/**
 * @brief find the prev node of a continual sequence in a loop list
 *
 * @param pkglst: the list
 * @param itins: the current node
 *
 * @return the first node, end() on error
 */
std::vector<ds3packet_ccf_t *>::iterator
ds3pktlstccf_prev (std::vector<ds3packet_ccf_t *> & pkglst, std::vector<ds3packet_ccf_t *>::iterator & itins)
{
    std::vector<ds3packet_ccf_t *>::iterator itnext = itins;
    if (itins == pkglst.end()) {
        return pkglst.end();
    }
    if (itins == pkglst.begin()) {
        itnext = pkglst.end();
    }
    itnext --;
    if (itnext == itins) {
        return pkglst.end();
    }
    return itnext;
}


        //if ((*itins)->get_header().sequence >= 8191) {
            /* ccf.sequence only has 13bits! = 8192 */

/**
 * @brief find the first node of a continual sequence in a loop list
 *
 * @param pkglst: the list
 * @param itins: the current node
 *
 * @return the first node, end() on error
 */
std::vector<ds3packet_ccf_t *>::iterator
ds3pktlstccf_find_first (std::vector<ds3packet_ccf_t *> & pkglst, std::vector<ds3packet_ccf_t *>::iterator & itins)
{
    // find the left most and right most positions which have continual sequence number
    std::vector<ds3packet_ccf_t *>::iterator itprev = itins;
    std::vector<ds3packet_ccf_t *>::iterator itleft = itins;

    itprev = ds3pktlstccf_prev (pkglst, itins);
    if (pkglst.end() == itprev) {
        assert(pkglst.size() == 1);
        return itins;
    }
    for (; (itleft != itins) && (itleft != pkglst.end()); itleft = ds3pktlstccf_prev (pkglst, itleft)) {
        if ((*itleft)->get_header().sequence + 1 != (*itprev)->get_header().sequence) {
            break;
        }
        itprev = itleft;
    }
    if (itleft != pkglst.end()) {
        itleft = ds3pktlstccf_next (pkglst, itleft);
    } else {
        if (itprev != itleft) {
            if ((*itleft)->get_header().sequence + 1 != (*itprev)->get_header().sequence) {
                itleft = itprev;
            }
        }
    }
    return itleft;
}

/**
 * @brief find the first node of a continual sequence in a loop list
 *
 * @param pkglst: the list
 * @param itins: the current node
 *
 * @return the first node, end() on error
 */
std::vector<ds3packet_ccf_t *>::iterator
ds3pktlstccf_find_last (std::vector<ds3packet_ccf_t *> & pkglst, std::vector<ds3packet_ccf_t *>::iterator & itins)
{
    // find the left most and right most positions which have continual sequence number
    std::vector<ds3packet_ccf_t *>::iterator itprev = itins;
    std::vector<ds3packet_ccf_t *>::iterator itright = itins;
    itprev = itright;
    itright = ds3pktlstccf_next (pkglst, itright);
    for (; (itright != itins) && (itright != pkglst.end()); ) {
        if ((*itprev)->get_header().sequence + 1 != (*itright)->get_header().sequence) {
            break;
        }
        itprev = itright;
        itright = ds3pktlstccf_next (pkglst, itright);
    }

    return itright;
}

std::vector<ds3packet_ccf_t *>::iterator
ds3pktlstccf_erase (std::vector<ds3packet_ccf_t *> & pkglst, std::vector<ds3packet_ccf_t *>::iterator & itins)
{
    std::vector<ds3packet_ccf_t *>::iterator itret;
    itret = pkglst.erase(itins);
    if (pkglst.end() == itret) {
        if (pkglst.size() > 0) {
            itret = pkglst.begin();
        }
    }
    return itret;
}

// erase the nodes between [itb, ite)
std::vector<ds3packet_ccf_t *>::iterator
ds3pktlstccf_erase (std::vector<ds3packet_ccf_t *> & pkglst
    , std::vector<ds3packet_ccf_t *>::iterator & itb
    , std::vector<ds3packet_ccf_t *>::iterator & ite)
{
    std::vector<ds3packet_ccf_t *>::iterator itret;
    itret = pkglst.erase(itb);
    itb = itret;
    for ( ; (pkglst.end() == itret) && (itret != ite); ) {
        itret = pkglst.erase(itret);
    }
    if (pkglst.end() == itret) {
        if (pkglst.size() > 0) {
            itret = pkglst.begin();
        }
    }
    return itret;
}

// the item between [itleft, itright)
ssize_t
ds3pktlstccf_distance (std::vector<ds3packet_ccf_t *> & pkglst
    , std::vector<ds3packet_ccf_t *>::iterator itleft
    , std::vector<ds3packet_ccf_t *>::iterator itright)
{
    size_t off1 = (itleft - pkglst.begin());
    size_t off2 = (itright - pkglst.begin());
    if (off1 <= off2) {
        return off2 - off1;
    }
    return (off1 + (pkglst.size() - off2));
}


// erase the node between it1st and itleft, then update the value of these itxxx
void
ds3pktlstccf_erase_update (std::vector<ds3packet_ccf_t *> & pkglst
    , std::vector<ds3packet_ccf_t *>::iterator & it1st
    , std::vector<ds3packet_ccf_t *>::iterator & itleft
    , std::vector<ds3packet_ccf_t *>::iterator & itright
    )
{
    std::cout << "pkg end-begin=" << (pkglst.end() - pkglst.begin()) << std::endl;
    size_t off1 = (itleft - pkglst.begin());
    size_t off2 = (itright - pkglst.begin());
    size_t off3 = (it1st - pkglst.begin());
    size_t numrm = 0;
    if (pkglst.size() > 0) {
        if (off2 >= off3) {
            /* | -- 1st XXX left -- right -- |  */
            numrm = (off1 - off3);
            assert (numrm == ds3pktlstccf_distance(pkglst, it1st, itleft));
        } else {
            if (off1 >= off3) {
                /* | -- right -- 1st XXX left -- |  */
                numrm = (off1 - off3);
                assert (numrm == ds3pktlstccf_distance(pkglst, it1st, itleft));
            } else {
                /* | XX left -- right -- 1st XX |  */
                numrm = (off1 + (pkglst.size() - off3));
                assert (numrm == ds3pktlstccf_distance(pkglst, pkglst.begin(), itleft) + ds3pktlstccf_distance(pkglst, itright, pkglst.end()));
            }
        }
    }
    ds3pktlstccf_erase (pkglst, it1st, itleft);
    if (pkglst.size() < 1) {
        assert (pkglst.begin() == pkglst.end());
        itleft = itright = pkglst.end();
    } else {
        if (off2 >= off3) {
            /* | -- 1st XXX left -- right -- |  */
            numrm = (off1 - off3);
            itleft = pkglst.begin() + (off1 - numrm);
            itright = pkglst.begin() + (off2 - numrm);
        } else {
            if (off1 >= off3) {
                /* | -- right -- 1st XXX left -- |  */
                numrm = (off1 - off3);
                itleft = pkglst.begin() + (off3 - numrm);
                itright = pkglst.begin() + off2;
            } else {
                /* | XX left -- right -- 1st XX |  */
                numrm = (off1 + (pkglst.size() - off3));
                assert (off3 >= pkglst.size());
                itleft = pkglst.begin() + (off3 - pkglst.size());
                itright = pkglst.begin() + (off2 - (off3 - pkglst.size()));
            }
        }
    }
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
#if CCFDEBUG
    std::cout << "ds3_ccf_unpack_t::process_packet got packet:" << std::endl;
    p->dump();
#endif

    ds3packet_ccf_t* pktin = dynamic_cast<ds3packet_ccf_t *>(p);
    assert (NULL != pktin);
#if CCFDEBUG
    if (pktin->get_header().sequence == 8191) {
        std::cout << "got seq 8191!" << std::endl;
    }
#endif
    // add p to sortedPackets
    std::vector<ds3packet_ccf_t *>::iterator itins = pkglst.begin();
    if (NULL != p) {
        // get the piggyback request
        ds3hdr_ccf_t & ccfhdr = pktin->get_header();
        if (ccfhdr.request > 0) {
            this->signify_piggyback (ccfhdr.sc, ccfhdr.request * this->get_pbmultiplier());
        }

        pktin->set_procpos_next(0);
        pktin->set_procpos_prev(0);
        if (ccfhdr.pfi == 1) {
            pktin->set_procpos_prev(ccfhdr.offmac);
            pktin->set_procpos_next(ccfhdr.offmac);
        }
        std::vector<ds3packet_ccf_t *>::iterator itup = pkglst.begin();
        itup = std::upper_bound (pkglst.begin(), pkglst.end(), pktin, compare_ccfpktp);
        itins = pkglst.insert(itup, pktin);
    }

    // find the left most and right most positions which have continual sequence number
    std::vector<ds3packet_ccf_t *>::iterator itleft = itins;
    std::vector<ds3packet_ccf_t *>::iterator itright = itins;
    itleft = ds3pktlstccf_find_first (pkglst, itins);
    itright = ds3pktlstccf_find_last (pkglst, itins);

    // debug:
    //assert (itright == pkglst.end());

    size_t off;
    ds3_packet_buffer_t hdrbuf; //std::vector<uint8_t> hdrbuf; /* buffer for MAC header and/or content */
    std::vector<ds3packet_ccf_t *>::iterator it1st = itleft; /* record the first segment position that is the begin of MAC header */

#define USE_DS3_MICRO 0
/** set the ccfhdr.offmac to 0 to indicate that the data before the first MAC hdr is processed */
//#define DS3PKGLST_SET_PROCESSED_OFFMAC(itleft)
/** remove the processed/corrupted segments */
//#define DS3PKGLST_REMOVE()

    ssize_t szmhdr = -1; /* the size of next sub-block, (header+content) */
    //ds3hdr_mac_t machdr; memset (&machdr, 0, sizeof (machdr));
    bool flg_data_left = false; /* use the left data of procpos_prev to fill hdrbuf */
    bool flg_data_right = false;  /* use the right data of procpos_next to fill hdrbuf */

    // find the first segment contains the MAC header
    for (; (itleft != pkglst.end()) /* && (itleft != itright)*/; ) {

        if ((*itleft)->get_header().pfi == 1) {
            // find the next unprocessed MAC header
            assert ((*itleft)->get_header().pfi == 1);
            off = (*itleft)->get_header().offmac;
            assert (off <= (*itleft)->get_procpos_next());
            assert (off >= (*itleft)->get_procpos_prev());
            if (off > (*itleft)->get_procpos_next()) {
                (*itleft)->set_procpos_next(off);
            }
        }
        off = (*itleft)->get_procpos_next();
        //std::vector<uint8_t> & cntbufref = (*itleft)->get_content_ref();
        ds3_packet_buffer_t & cntbufref = (*itleft)->get_content_ref();

		// check if the CCF segment was complete processed.
        if ((ssize_t)off >= cntbufref.size()) {
            // this segment is processed from the start of offmac to the end
            assert ((ssize_t)off == (*itleft)->get_content_ref().size());
            if ((*itleft)->get_procpos_prev() < 1) {
                // there's no data before the first MAC header, or no MAC header
                assert ((*itleft)->get_procpos_prev() == 0);

                this->recycle_packet( *itleft );

                ssize_t dis = ds3pktlstccf_distance (pkglst, itleft, itright);
                itleft = ds3pktlstccf_erase (pkglst, itleft);
                itright = itleft;
                for (size_t i = 0; i + 1 < dis; i ++) {
                    itright = ds3pktlstccf_next_pivot (pkglst, itright, itleft);
                }
                continue;
            }
        }
{
        // check if we can get MAC header
        szmhdr = -1; /* the size of next sub-block, (header+content) */
        //ds3hdr_mac_t machdr; memset (&machdr, 0, sizeof (machdr));
        flg_data_left = false; /* use the left data of procpos_prev to fill hdrbuf */
        flg_data_right = false;  /* use the right data of procpos_next to fill hdrbuf */

        if (hdrbuf.size() <= 0) {
            // this is the first segment of a MAC packet

            // make sure this segment has MAC header!!
            if ((*itleft)->get_header().pfi == 0) {
                // the whole segment is part of packet, not MAC header!
                // we should skip to next one!
                itleft = ds3pktlstccf_next_pivot (pkglst, itleft, itright);
                continue;
            }

            assert (hdrbuf.size() == 0);
            it1st = itleft;

            // hdrbuf.insert (hdrbuf.end(), cntbufref.begin() + off, cntbufref.end());
            hdrbuf.insert (hdrbuf.end(), &cntbufref, cntbufref.begin() + off, cntbufref.end());

            flg_data_right = true;
            // try to find a new MAC header

            //szmhdr = ds3hdr_mac_from_nbs (&hdrbuf[0], hdrbuf.size(), &machdr); if (szmhdr > 0) { szmhdr += machdr.length; }
            szmhdr = hdrbuf.block_size_at (0); // the size of hdr+content

            if (szmhdr <= 0) {
                // no enough header bytes
                // wait for next one?
                itleft = ds3pktlstccf_next_pivot (pkglst, itleft, itright);
                continue;
            } else {
                // get the header successfully
                if (hdrbuf.size() < (szmhdr)) {
                    itleft = ds3pktlstccf_next_pivot (pkglst, itleft, itright);
                    continue;
                }
            }

        } else {
            // there's incomplete MAC header in previous segment
            bool flg_corrupted = false;
            bool flg_continue = false;
            if ((*itleft)->get_header().pfi == 1) {
                // this should be the last segment of the packet
                // attach the content from the buffer to hdrbuf by size of offmac
                assert ((*itleft)->get_header().offmac > 0);
                assert ((*itleft)->get_header().offmac == (*itleft)->get_procpos_prev ());
                hdrbuf.insert (hdrbuf.end(), &cntbufref, cntbufref.begin(), cntbufref.begin() + (*itleft)->get_procpos_prev()); //hdrbuf.insert (hdrbuf.end(), cntbufref.begin(), cntbufref.begin() + (*itleft)->get_procpos_prev());
                flg_data_left = true;
            } else {
                // this whole segment is a part of the packet
                assert ((*itleft)->get_procpos_next() == 0);
                assert (off == (*itleft)->get_procpos_next ());
                hdrbuf.insert (hdrbuf.end(), &cntbufref, cntbufref.begin() + off, cntbufref.end()); // hdrbuf.insert (hdrbuf.end(), cntbufref.begin() + off, cntbufref.end());
                flg_data_right = true;
            }
            //szmhdr = ds3hdr_mac_from_nbs (&hdrbuf[0], hdrbuf.size(), &machdr); if (szmhdr > 0) { szmhdr += machdr.length; }
            szmhdr = hdrbuf.block_size_at (0); // the size of hdr+content
            if (szmhdr <= 0) {
                if ((*itleft)->get_header().pfi == 1) {
                    // Error: impossible to here! or there's error in the packet
                    flg_corrupted = true;
#if CCFDEBUG
std::cout << "Error, corrupted CCF found: hdrbuf.size(=" << hdrbuf.size() << ", szmhdr=" << szmhdr << " <=0, and pfi=1" << std::endl;
#endif
                } else {
                    // no enough header bytes
                    // wait for next one?
                    flg_continue = true;
                }
            } else {
                // get the header successfully
                if (hdrbuf.size() < (szmhdr)) {
                    if ((*itleft)->get_header().pfi == 1) {
                        // Error: corrupted packet
                        flg_corrupted = true;
#if CCFDEBUG
std::cout << "Error, corrupted CCF found: hdrbuf.size(=" << hdrbuf.size() << ") < szmhdr=" << szmhdr
    << ", and pfi=1"
    << ", read offset =" << (*itleft)->get_procpos_next()
    << std::endl;
assert (0);
#endif
                    } else {
                        // no enough header bytes
                        // wait for next one?
                    }
                    szmhdr = 0; // reset the header so that it continues
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
                    /* delete nodes in a loop list */
                    if ((*it1st)->get_procpos_prev () > 0) {
                        (*it1st)->set_procpos_next ((*it1st)->get_content_ref ().size()); // (*it1st)->set_procpos_next((*it1st)->size());
                        it1st = ds3pktlstccf_next_pivot (pkglst, it1st, itleft);
                    }
                    if ((it1st != itleft) && (it1st != pkglst.begin())) { /*FIXME: delete nodes in a loop list!*/
                        std::vector<ds3packet_ccf_t *>::iterator ittmp = it1st;
                        for (; ittmp != itleft; ittmp = ds3pktlstccf_next_pivot (pkglst, ittmp, itright)) {
#if CCFDEBUG
std::cout << "Error, corrupted CCF dropped!!!" << std::endl;
#endif
                            this->drop_packet( *ittmp );
                        }
                        ds3pktlstccf_erase_update (pkglst, it1st, itleft, itright);
                    }
                }
                it1st = itleft;
#if USE_DS3_MICRO // 3
                DS3PKGLST_SET_PROCESSED_OFFMAC (itleft);
#else // 3
                /* we also set the procpos_prev to 0 to indicate that the data before the first MAC hdr is processed */
                if ( (*itleft)->get_procpos_next() < (*itleft)->get_header().offmac ) {
                    assert ((*itleft)->get_procpos_prev () == (*itleft)->get_header().offmac);
                    (*itleft)->set_procpos_next ((*itleft)->get_header().offmac);
                }
                if (flg_data_left) {
                    (*itleft)->set_procpos_prev (0);
                }
#endif // 3
#endif // 2
            }
            if (flg_continue) {
                itleft = ds3pktlstccf_next_pivot (pkglst, itleft, itright);
                continue;
            }
        }
        if (szmhdr > 0) {
            // got a mac header
#if USE_DS3_MICRO // 1
            DS3PKGLST_PROCESS_BODY();
#else // 1
            if (hdrbuf.size() >= (szmhdr)) {
                assert (hdrbuf.size() >= (szmhdr));
                if (flg_data_left) {
                    // do nothing
                }
                if (flg_data_right) {
                    size_t szbk = (hdrbuf.size() - (size_t)(szmhdr));
                    size_t szrest = (cntbufref.end() - (cntbufref.begin() + off));
                    size_t szadd = szrest - szbk;
                    /* resize the buffer according to machdr.length */
                    std::cout << "the size of data in the buffer NOT belonging to the packet: " << szbk << std::endl;
                    std::cout << "the size of data were read in current segment: " << szrest << std::endl;
                    std::cout << "set the next offset from " << off << " to " << (off + szadd) << std::endl;
                    (*itleft)->set_procpos_next (off + szadd);
                }

                hdrbuf.resize((size_t)(szmhdr));
                /* extract the packet */
                this->signify_packet (hdrbuf);
                hdrbuf.resize(0);
                /* remove the processed segments */
#if USE_DS3_MICRO // 2
                DS3PKGLST_REMOVE_OK ();
#else // 2
                if (it1st != itleft) {
                    if ((*it1st)->get_procpos_prev() > 0) {
                        // this is the start of segment, and it has other content at the begining,
                        // so we just set the last position to max position:
                        (*it1st)->set_procpos_next ((*it1st)->get_content_ref ().size()); // (*it1st)->set_procpos_next ((*it1st)->size());
                        it1st = ds3pktlstccf_next_pivot (pkglst, it1st, itleft);
                    }
                    if ((it1st != itleft) && (it1st != pkglst.end())) {
                        /* delete nodes in a loop list! */
                        std::vector<ds3packet_ccf_t *>::iterator ittmp = it1st;
                        for (; ittmp != itleft; ittmp ++) {
                            this->recycle_packet( *ittmp );
                        }

                        ds3pktlstccf_erase_update (pkglst, it1st, itleft, itright);
                    }
                }
                it1st = itleft;
#if USE_DS3_MICRO // 3
                DS3PKGLST_SET_PROCESSED_OFFMAC (itleft);
#else // 3
                /* we also set the ccfhdr.offmac to 0 to indicate that the data before the first MAC hdr is processed */
                if ( (*itleft)->get_procpos_next () < (*itleft)->get_header().offmac ) {
                    assert ((*itleft)->get_procpos_prev() == (*itleft)->get_header().offmac);
                    (*itleft)->set_procpos_next ((*itleft)->get_header().offmac);
                }
                if (flg_data_left) {
                    (*itleft)->set_procpos_prev(0);
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
}
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
#if CCFDEBUG
        std::cout << "ds3_ccf_pack_t::process_packet got packet:" << std::endl;
        p->dump();
#endif
        p->reset_procpos(); /* reset the processed position to 0 */
        this->pktlst.push_back (p);
    }
    size_t numSeg = 0;
    size_t szMax = 0;
    size_t szCur = 0;
    size_t szNext = 0;
    ds3hdr_ccf_t ccfhdr;
    ds3_packet_buffer_t buffer; //std::vector<uint8_t> buffer;
    // remove the timeout grants
    std::vector<ds3_grant_t>::iterator itg;
    double tmcur = this->current_time();
    for (itg = this->grantlst.begin(); itg != this->grantlst.end(); itg ++) {
        if (tmcur > itg->get_time()) {
            /* invalid grant, delete it */
            std::cerr << "ds3ccf: Error invalid grant: current time=" << this->current_time()
                << ", time=" << (*itg).get_time()
                << ", size=" << (*itg).get_size()
                << ", channel=" << (*itg).get_channel_id()
                << std::endl;
            continue;
        }
        if (pktlst.size() < 1) {
            // empty
            break;
        }
        std::cerr << "ds3ccf: process grant: time=" << (*itg).get_time()
            << ", size=" << (*itg).get_size()
            << ", channel=" << (*itg).get_channel_id()
            << std::endl;
        szMax = itg->get_size();
        assert (szMax >= (size_t)ds3hdr_ccf_to_nbs(NULL, 0, NULL));
        szCur = ds3hdr_ccf_to_nbs(NULL, 0, NULL);
        buffer.resize (0);
        memset (&ccfhdr, 0, sizeof(ccfhdr));
        for (; szCur < szMax;) {
            assert (pktlst.size() > 0);
            assert (NULL != pktlst[0]);
            assert (pktlst[0]->get_size() > 0);
            if (0 == pktlst[0]->get_procpos_next()) {
                /* It's the beginning of the packet */
                if (0 == ccfhdr.pfi) {
                    ccfhdr.pfi = 1;
                    assert (szCur >= (size_t)ds3hdr_ccf_to_nbs(NULL, 0, NULL));
                    ccfhdr.offmac = (szCur - ds3hdr_ccf_to_nbs(NULL, 0, NULL));
                }
            }
            assert (pktlst[0]->get_size() > pktlst[0]->get_procpos_next());
            szNext = pktlst[0]->get_size() - pktlst[0]->get_procpos_next();
            if (szCur + szNext > szMax) {
                szNext = szMax - szCur;
            }

            /* fill the buffer */
            //ssize_t ret1 = pktlst[0]->get_pkt_bytes (pktlst[0]->get_procpos(), buffer, szNext);
            //assert ((size_t)ret1 == szNext);
            assert (buffer.size() >= 0);
            size_t szorig1 = buffer.size();
            ds3_packet_buffer_t * retbuf = pktlst[0]->insert_to (buffer.size(), &buffer, pktlst[0]->get_procpos_next(), pktlst[0]->get_procpos_next() + szNext);
            if (NULL == retbuf) {
                // error, break;
                break;
            }
            assert (retbuf == &buffer);
            assert ((ssize_t)(szorig1 + szNext) == buffer.size());

            szCur += szNext;
            pktlst[0]->set_procpos_next (pktlst[0]->get_procpos_next () + szNext);
            if (pktlst[0]->get_procpos_next () >= pktlst[0]->get_size()) {
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
            if ( (this->piggyback_inc > 0)
#if USE_DS3_LATESNDPIG
                 && (itg == this->grantlst.end())
#endif
                )
            {
                ccfhdr.request = this->piggyback_inc / this->get_pbmultiplier();
                this->piggyback_inc = 0;
            }
            ccfhdr.sequence = this->get_next_sequence();
            ccfhdr.sc = this->scid;
            /* set the CCF header */
            ds3packet_ccf_t * ccfpkt = new ds3packet_ccf_t();
            assert (NULL != ccfpkt);
            ccfpkt->set_header(&ccfhdr);
            ccfpkt->set_content(&buffer);
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
ds3_ccf_pack_t::add_grants (std::vector<ds3_grant_t> & grants)
{
    grantlst.insert (grantlst.end(), grants.begin(), grants.end());
    std::sort (grantlst.begin(), grantlst.end());

    process_packet (NULL);
    return 0;
}

int
ds3_ccf_pack_t::add_grant (ds3_grant_t & grant)
{
    grantlst.insert (grantlst.end(), grant);
    std::sort (grantlst.begin(), grantlst.end());
    process_packet (NULL);
    return 0;
}
