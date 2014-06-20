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
#include <string.h>     // memcmp
#include <assert.h>

#include <iostream>
#include <vector>
#include <algorithm>

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

/**
 * @brief The CCF segment header structure
 */
typedef struct _ds3hdr_ccf_t {
    uint16_t pfi        :  1; /**< PFI */
    uint16_t r          :  1; /**< Reserved */
    uint16_t offmac     : 14; /**< Pointer to MAC header */
    uint16_t sequence   : 13; /**< Sequence # */
    uint16_t sc         :  3; /**< SID Cluster ID */
    uint16_t request;         /**< Request */
    uint16_t hcs;             /**< HCS */
} ds3hdr_ccf_t;

ssize_t ds3hdr_ccf_from_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_ccf_t * rethdr);

ssize_t ds3hdr_ccf_to_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_ccf_t * refhdr);

/**
 * @brief The DOCSIS MAC header structure
 */
typedef struct _ds3hdr_mac_t {
    uint16_t sequence; /**< The sequence # of the MAC packet */
    uint16_t length; /**< The length of the data in the MAC packet */
} ds3hdr_mac_t;

ssize_t ds3hdr_mac_to_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_mac_t * refhdr);

ssize_t ds3hdr_mac_from_nbs (uint8_t *nbsbuf, size_t szbuf, ds3hdr_mac_t * rethdr);

/**
 * @brief The base class for all types of the packet
 */
class ds3packet_t {
public:
    ds3packet_t() : pos_next(0) {}
    virtual ~ds3packet_t() { std::cout << "Destroy " << __func__ << std::endl; } /**< the children class should re-implement this destructor to release resource correctly */

    virtual ssize_t get_pkt_bytes (size_t pos, uint8_t *nbsbuf, size_t szbuf);
    ssize_t get_pkt_bytes (size_t pos, std::vector<uint8_t> & nbsbuf, size_t szbuf);
    size_t get_size() { return to_nbs(NULL,0); } /**< return the size of the packet, including the packet header, */

    size_t get_procpos () const { return pos_next; } /**< get the current (read) position of the raw packet data */
    /**
     * @brief set the current (read) position of the raw packet data
     * @param s : the new position
     * @return N/A
     */
    void set_procpos (size_t s) { pos_next = s; }

    /**
     * @brief convert the packet to network byte sequence and save it to nbsbuf, include packet header
     * @param nbsbuf : the buffer to be filled, in network byte sequence
     * @param szbuf : the size requested to be filled
     * @return the size of data copied to buffer, >0 on success, < 0 on error
     */
    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf) { std::cout << "wrong " << __func__ << std::endl; /* should never reach to this function, the d3packet_t should be a abstract class! */assert(0); return 0; }

    /**
     * @brief read the buffer in network byte sequence and save it to structure, include packet header
     * @param nbsbuf : the buffer to be read, in network byte sequence
     * @param szbuf : the size of the buffer
     * @return the size of data processed, >0 on success, < 0 on error
     */
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf) { std::cout << "wrong " << __func__ << std::endl; /* should never reach to this function, the d3packet_t should be a abstract class! */assert(0); return 0; }

    /**
     * @brief convert the packet header to network byte sequence and save it to nbsbuf
     * @param nbsbuf : the buffer to be filled, in network byte sequence
     * @param szbuf : the size requested to be filled
     * @return the size of data copied to buffer, >0 on success, < 0 on error
     */
    virtual ssize_t hdr_to_nbs (uint8_t *nbsbuf, size_t szbuf) { std::cout << "wrong " << __func__ << std::endl; /* should never reach to this function, the d3packet_t should be a abstract class! */assert(0); return 0; } /**< get bytes of the packet, include MAC header */

    /**
     * @brief set the content of the packet, not include the header
     * @param nbsbuf : the buffer contains the content
     * @param szbuf : the size of the data in the buffer
     * @return 0 on success, < 0 on error
     */
    virtual int set_content (uint8_t *nbsbuf, size_t szbuf);

    /**
     * @brief set the content of the packet, not include the header
     * @param newbuf : the buffer contains the content
     * @return 0 on success, < 0 on error
     */
    virtual int set_content (std::vector<uint8_t> & newbuf) { buffer = newbuf; return 0; }

    /**
     * @brief set the content of the packet, not include the header
     * @param begin1 : the start position of buffer
     * @param end1 : the end position of buffer
     * @return 0 on success, < 0 on error
     */
    virtual int set_content (std::vector<uint8_t>::iterator & begin1, std::vector<uint8_t>::iterator & end1) { buffer.resize(0); std::copy (begin1, end1, buffer.begin()); return 0; }

    std::vector<uint8_t> & get_content_ref (void) { return this->buffer; } /**< get the reference of the data content buffer */

    virtual void dump (void) { std::cout << "wrong " << __func__ << std::endl; /* should never reach to this function, the d3packet_t should be a abstract class! */assert(0); } /**< dump the content of packet */

protected:
    std::vector<uint8_t> buffer; /**< the content buffer */

    void dump_content (void);

private:
    size_t pos_next; /**< the current processed start possition; used for send/recv-ing packet/segment */
};

/**
 * @brief The packet class for DS3 CCF segment
 */
class ds3packet_ccf_t : public ds3packet_t {
public:
    virtual ~ds3packet_ccf_t() { std::cout << "Destroy " << __func__ << std::endl; memset (&(this->ccfhdr), 0, sizeof(this->ccfhdr)); }

    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf);
    virtual ssize_t hdr_to_nbs (uint8_t *nbsbuf, size_t szbuf) { return ds3hdr_ccf_to_nbs (nbsbuf, szbuf, &(this->ccfhdr)); }

    virtual void dump (void);

    /**
     * @brief set the CCF segment header
     * @param chdr : the CCF header structure to be saved
     * @return 0 on success, < 0 on error
     */
    int set_header (ds3hdr_ccf_t * chdr) { if (NULL == chdr) {return -1;} memmove (&(this->ccfhdr), chdr, sizeof (*chdr)); return 0; }
    ds3hdr_ccf_t & get_header (void) { return ccfhdr; } /**< get a reference of the CCF segment header */

private:
    ds3hdr_ccf_t ccfhdr; /**< the CCF segment header */
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
    virtual int signify_packet (std::vector<uint8_t> & macbuffer) = 0;
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
