/**
 * @file    ds3pktccf.h
 * @brief   process DOCSIS CCF header
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-12
 * @copyright Yunhui Fu (2014)
 */
#ifndef _DS3PKGCCF_H
#define _DS3PKGCCF_H

#include <stdint.h> // uint16_t
#include <string.h> // memcmp
#include <assert.h>

#include <iostream>
#include <vector>
#include <algorithm>

#include "ds3pktcnt.h"

/**
 * @brief The event type for state machine
 *
 *  It should be redefined by the main module
 */
#define ds3event_t int
#define DS3EVT_MAP      0x01 /**< Event MAP packet received */
#define DS3EVT_PKT      0x02 /**< Event data packet received */
#define DS3EVT_TMRPKT   0x03 /**< Event timer timeout for sending data packet/segment */
#define DS3EVT_TMRREQ   0x04 /**< Event timer timeout for sending request packet */

#define DS3_MULTIPLIER_REQUEST 8 /**< the value of the default Multiplier (Number of Bytes Requested in Annex C) */

const char * ds3_event2desc (ds3event_t e);

/**
 * @brief The base class for all types of the packet
 */
class ds3packet_t {
public:
#if CCFDEBUG
    virtual void dump (void) { DS3_WRONGFUNC_RET(); } /**< dump the content of packet */
    virtual uint8_t & at(size_t i);
#endif

    ds3packet_t() : pos_next(0) {}
    virtual ~ds3packet_t() { std::cout << "Destroy " << __func__ << std::endl; } /**< the children class should re-implement this destructor to release resource correctly */

    size_t get_size() { return to_nbs(NULL,0); } /**< return the size of the packet, including the packet header, */
    size_t size() { return to_nbs(NULL,0); } /**< return the size of the packet, including the packet header, */

    size_t get_procpos () const { return pos_next; } /**< get the current (read) position of the raw packet data */
    /**
     * @brief set the current (read) position of the raw packet data
     * @param s : the new position
     * @return N/A
     */
    void set_procpos (size_t s) { pos_next = s; }

    /**
     * @brief convert the packet to network byte sequence and save it to nbsbuf, including the packet header
     * @param nbsbuf : the buffer to be filled, in network byte sequence
     * @param szbuf : the size requested to be filled
     * @return the size of data copied to buffer, >0 on success, < 0 on error
     */
    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf) { DS3_WRONGFUNC_RETVAL(-1); }

    /**
     * @brief read the buffer in network byte sequence and save it to structure, including the packet header
     * @param nbsbuf : the buffer to be read, in network byte sequence
     * @param szbuf : the size of the buffer
     * @return the size of data processed, >0 on success, < 0 on error
     */
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf) { DS3_WRONGFUNC_RETVAL(-1); }
    virtual ssize_t from_nbs (ds3_packet_buffer_t *buf, size_t pos) { DS3_WRONGFUNC_RETVAL(-1); }

    /**
     * @brief set the content of the packet, not include the header
     * @param nbsbuf : the buffer contains the content
     * @param szbuf : the size of the data in the buffer
     * @return 0 on success, < 0 on error
     */
    //virtual int set_content (uint8_t *nbsbuf, size_t szbuf);

    /**
     * @brief set the content of the packet, not include the header
     * @param newbuf : the buffer contains the content
     * @return 0 on success, < 0 on error
     */
    //virtual int set_content (std::vector<uint8_t> & newbuf) { buffer = newbuf; return 0; }

    /**
     * @brief set the content of the packet, not include the header
     * @param begin1 : the start position of buffer
     * @param end1 : the end position of buffer
     * @return 0 on success, < 0 on error
     */
    //virtual int set_content (std::vector<uint8_t>::iterator & begin1, std::vector<uint8_t>::iterator & end1) { buffer.resize(0); std::copy (begin1, end1, buffer.begin()); return 0; }


    /**
     * @brief set the content of the packet, not include the header
     * @param peer : the new content
     * @return 0 on success, < 0 on error
     */
    virtual int set_content (ds3_packet_buffer_t *peer)
        { this->buffer.resize(0); if (0 > this->insert_content(0, peer, peer->begin(), peer->end())) { return -1; } return 0; }

    /**
     * @brief insert content from peer
     *
     * @param pos_self : [in] the insert position(self)
     * @param peer : [in,out] the buffer to be copied by this function
     * @param begin_peer : [in] the start position of the content (peer)
     * @param end_peer : [in] the end position of the content (peer)
     *
     * @return the size of data copied on success; < 0 on error
     *
     * insert content from peer. not include the header
     */
    ssize_t insert_content (size_t pos_self, ds3_packet_buffer_t *peer, size_t begin_peer, size_t end_peer)
        { return this->buffer.insert(pos_self, peer, begin_peer, end_peer); }

    /**
     * @brief get the raw data bytes(network byte sequence) of the packet
     *
     * @param pos_peer : [in] the insert position of buffer
     * @param peer : [out] the buffer to be filled
     * @param begin_self : [in] the start position of the byte sequence, the position is start from the packet header
     * @param end_self : [in] the end position
     *
     * @return a new buffer(if peer==NULL) or peer on success, NULL on error
     *
     * get the raw data bytes(network byte sequence) of the packet
     *
     */
    virtual ds3_packet_buffer_t * insert_to (size_t pos_peer, ds3_packet_buffer_t *peer, size_t begin_self, size_t end_self)
        { DS3_WRONGFUNC_RETVAL(NULL); }

    //std::vector<uint8_t> & get_content_ref (void) { return this->buffer; } /**< get the reference of the data content buffer */
    ds3_packet_buffer_t & get_content_ref (void) { return this->buffer; } /**< get the reference of the data content buffer */

protected:
    ds3_packet_buffer_t buffer; // std::vector<uint8_t> buffer; /**< the content buffer */

    /**
     * @brief convert the packet header to network byte sequence and save it to nbsbuf
     * @param nbsbuf : the buffer to be filled, in network byte sequence
     * @param szbuf : the size requested to be filled
     * @return the size of data copied to buffer, >0 on success, < 0 on error
     */
    //virtual ssize_t hdr_to_nbs (uint8_t *nbsbuf, size_t szbuf) { DS3_WRONGFUNC_RETVAL(-1); } /**< get bytes of the packet, include MAC header */

#if CCFDEBUG
    void dump_content (void) { this->get_content_ref().dump(); } /**< dump the content */
#endif

private:
    size_t pos_next; /**< the current processed start possition; used for send/recv-ing packet/segment */
};

/* check the arguments for ds3packet_t::insert_to() */
#define DS3_DYNCST_CHKRET_DS3PKT_BUFFER(ds3_real_type, arg_peer) \
    ds3_real_type *peer = NULL; \
    bool flg_peer_is_new = false; \
    if (NULL == (arg_peer)) { \
        /* create a new buf, and copy itself from [begin_self, end_self], return the new buf */ \
        (arg_peer) = peer = new ds3_real_type (); \
        flg_peer_is_new = true; \
    } else { \
        peer = dynamic_cast<ds3_real_type *>(arg_peer); \
        if (NULL == peer) { \
            if (NULL != (arg_peer)->get_buffer()) { \
                /* it's a base class, and it stored the content from other ns2 content */ \
                peer = dynamic_cast<ds3_real_type *>((arg_peer)->get_buffer()); \
            } \
        } \
        if (NULL == peer) { \
            /* create a new one, and try to append to the current arg_peer */ \
            ds3_real_type p; \
            assert (NULL != (arg_peer)); \
            (arg_peer)->insert(0, &p, 0, 0); \
            if (NULL != (arg_peer)->get_buffer()) { \
                /* it's a base class, and it stored the content from other ns2 content */ \
                peer = dynamic_cast<ds3_real_type *>((arg_peer)->get_buffer()); \
            } \
        } \
    } \
    if (NULL == peer) { \
        assert (0); \
        return NULL; \
    } \
    if ((ssize_t)pos_peer > peer->size()) { \
        if (flg_peer_is_new) { free (peer); } \
        return NULL; \
    } \
    if (begin_self >= this->size()) { \
        /* do nothing */ \
        return (arg_peer); \
    } \
    if (end_self > this->size()) { \
        end_self = this->size(); \
    }

/**
 * @brief The packet class for DS3 CCF segment
 */
class ds3packet_ccf_t : public ds3packet_t {
public:
    /**
     * @brief set the CCF segment header
     * @param chdr : the CCF header structure to be saved
     * @return 0 on success, < 0 on error
     */
    int set_header (ds3hdr_ccf_t * chdr) { if (NULL == chdr) {return -1;} memmove (&(this->ccfhdr), chdr, sizeof (*chdr)); return 0; }
    ds3hdr_ccf_t & get_header (void) { return ccfhdr; } /**< get a reference of the CCF segment header */

#if CCFDEBUG
    virtual void dump (void);
    virtual uint8_t & at(size_t i);
#endif

    virtual ~ds3packet_ccf_t() { std::cout << "Destroy " << __func__ << std::endl; memset (&(this->ccfhdr), 0, sizeof(this->ccfhdr)); }

    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf);

    //virtual ds3_packet_buffer_t * insert_to (size_t pos_peer, ds3_packet_buffer_t *peer, size_t begin_self, size_t end_self);

private:
    ssize_t hdr_to_nbs (uint8_t *nbsbuf, size_t szbuf) { return ds3hdr_ccf_to_nbs (nbsbuf, szbuf, &(this->ccfhdr)); }
    ds3hdr_ccf_t ccfhdr; /**< the CCF segment header */
    uint8_t ccfhdrbuf[8]; /**< buffer for CCF header */
};

/**
 * @brief grant record class
 */
class ds3_grant_t {
public:
    int    get_channel_id() const { return channel_id; } /**< get the channel id field */
    double get_time() const { return time; } /**< get the time field */
    size_t get_size() const { return size; } /**< get the grant size field */

    void set_channel_id(int id) { channel_id = id; } /**< set the channel id field */
    void set_time(double tm) { time = tm; } /**< set the time field */
    void set_size(size_t sz) { size = sz; } /**< set the grant size field */

    //inline bool operator < (const ds3_grant_t & rhs) { return (this->get_time() < rhs.get_time()); } /**< for sorting the grant by time */

private:
    int channel_id;
    double time;
    size_t size;
};

/** compare the time of the grants, for sorting the grant by time */
inline bool operator < (const ds3_grant_t & lhs, const ds3_grant_t & rhs) { return (lhs.get_time() < rhs.get_time()); }

/**
 * @brief The base class for CCF pack/unpack algorithms
 */
class ds3_ccf_base_t {
public:
    virtual int process_packet (ds3packet_t *p) = 0; /**< add a new packet and process */

    ds3_ccf_base_t(size_t pbmul = 0) : multiplier_piggyback(pbmul) {}
    void set_pbmultiplier(size_t pbmul) { multiplier_piggyback = pbmul; } /**< set the Multiplier */
    size_t get_pbmultiplier(void) const { return multiplier_piggyback; } /**< get the Multiplier */

protected:
    virtual void recycle_packet (ds3packet_t *p) = 0; /**< a processed packet need to be deleted */
    virtual void drop_packet (ds3packet_t *p) = 0; /**< a un-processed packet need to be drop (caused by corruption?) */

    size_t multiplier_piggyback; /**< the Multiplier to Number of Bytes Requested (DOCSIS 3.1 spec Annex C) */
};

/**
 * @brief The class for CCF pack algorithms
 */
class ds3_ccf_pack_t : public ds3_ccf_base_t {
public:
    virtual int process_packet (ds3packet_t *p);

    ds3_ccf_pack_t () : sequence(0), piggyback_inc(0) {}
    int add_grants (std::vector<ds3_grant_t> & grants, size_t piggyback);

protected:
    /**
     * @brief start a timer for sending packet once timeout
     * @param abs_time : the abstruct time that the event should fire
     * @param evt : the event fired when timeout
     * @param p : the packet that should be passed in for processing event evt
     * @param channel_id : the channel id that the packet be transfered
     * @return 0 on success, < 0 on error
     */
    virtual int start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id) = 0;
    virtual double current_time (void) = 0; /**< get the current time */

private:
    uint16_t get_next_sequence (void) { uint16_t ret = this->sequence; this->sequence ++; this->sequence &= 0x1FFF; return ret; } /**< get next sequence number and increase the # for next request */
    uint16_t sequence; /**< a 13-bit length counter */

    std::vector<ds3packet_t *> pktlst; /**< the list of all MAC packets will be packed to CCF segments */
    std::vector<ds3_grant_t>   grantlst; /**< the list of all grants */
    size_t piggyback_inc; /**< the piggyback request value */
};

/**
 * @brief The class for CCF unpack algorithms
 */
class ds3_ccf_unpack_t : public ds3_ccf_base_t {
public:
    virtual int process_packet (ds3packet_t *p);

protected:
    /**
     * @brief signify that a new MAC packet was extracted from the segments received
     * @param macbuffer : the MAC packet raw data
     * @return 0 on success, < 0 on error
     */
    virtual int signify_packet (ds3_packet_buffer_t & macbuffer) = 0;
    /**
     * @brief signify that a piggyback request was extracted from the segments received
     * @param sc : SID Cluster ID
     * @param request : the piggyback request value
     * @return 0 on success, < 0 on error
     */
    virtual int signify_piggyback (int sc, size_t request) = 0;

private:
    std::vector<ds3packet_ccf_t *> pkglst;
};

#endif // _DS3PKGCCF_H
