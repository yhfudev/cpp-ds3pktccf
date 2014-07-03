/**
 * @file    ds3pktbuf.h
 * @brief   ds3 packet content buffer
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-20
 * @copyright Yunhui Fu (2014)
 *
 * To support both the NBS and NS2 Packet, we abstruct the packet's content to a ds3_packet_buffer_t.
 * So we can test the segmentation/assembly code with either the regular NBS packet format (it can also be used in a real project),
 * or Packet class format for NS2 simulator.
 *
 * There're two classes involved in this abstruction.
 * One is the ds3_packet_buffer_t, which will act as a buffer, you may think it is a standard std::vector<uint8_t>.
 * It only for store the data content of packet(s). Some times we may want to know the size of formated packet(sub-block)
 * in the data content, we can derived from the normal buffer class (ds3_packet_buffer_nbs_t) to a more specificate class (ds3_packet_buffer_nbsmac_t)
 * which can parse the actual size of the sub-block. This help the assembly processing to extract the enough data for extracting a complete packet.
 *
 * Another one is the ds3packet_t class, which has the complete interface to handle the packet header and the data content.
 * The class supply two types of APIs, one is for CCF, which support current read position; another one is for header/data,
 * which support set/get the header info and/or content.
 * The class have to include a ds3_packet_buffer_t member other than derived from it,
 * because the ds3packet_t is used internally(ds3packet_ccf_t) for CCF segmentation.
 */
#ifndef _DS3PKGCNT_H
#define _DS3PKGCNT_H

#include <stdint.h> // uint16_t
#include <string.h> // memcmp
#include <assert.h>

#include <iostream>
#include <vector>
#include <algorithm>

#include <typeinfo>

#if DEBUG
#define CCFDEBUG 1
#endif

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

#define DS3_WRONGFUNC_EXECEPTION() { \
    std::cout << "[" __FILE__ ":" << __LINE__ << "] wrong " << typeid(this).name() << "::" << __func__ << "() ! should never reach to this function, it should be a abstract function!" << std::endl; \
    assert(0); \
    throw (std::string ("not valid content")); \
    }

#define DS3_WRONGFUNC_RET() { \
    std::cout << "[" __FILE__ ":" << __LINE__ << "] wrong " << typeid(this).name() << "::" << __func__ << "() ! should never reach to this function, it should be a abstract function!" << std::endl; \
    assert(0); \
    return; \
    }

#define DS3_WRONGFUNC_RETVAL(val) {  \
    std::cout << "[" __FILE__ ":" << __LINE__ << "] wrong " << typeid(this).name() << "::" << __func__ << "() ! should never reach to this function, it should be a abstract function!" << std::endl; \
    assert(0); \
    return (val); \
    }

/**
 * @brief The base class for all types of the packet content
 *
 * This class is designed as a base class for the packet content.
 * It can handle any kinds of know or unknow(derived) contents,
 * by forcing the derived class implement insert_to() and copy_to().
 * The base class can then handle one type of the derived class,
 * it's enough for the purpose of CCF.
 */
class ds3_packet_buffer_t {
public:
#if CCFDEBUG
    //static char * type2desc (ds3_packet_buffer_t *);
    virtual void dump (void)
        {
            if (this->contents_buffer) {
                return this->contents_buffer->dump();
            }
            DS3_WRONGFUNC_RET();
        }
#endif

    virtual ~ds3_packet_buffer_t()
        {
            if (this->contents_buffer) {
                delete this->contents_buffer;
            }
        }

    ds3_packet_buffer_t() : contents_buffer(NULL) {}
    virtual ds3_packet_buffer_t * create(void)
        {
            if (this->contents_buffer) {
                return this->contents_buffer->create();
            }
            return new ds3_packet_buffer_t();
        }
    /* force the parrent pointer use the derived class's create() to get the correct instance */
    virtual ds3_packet_buffer_t * create(ds3_packet_buffer_t * peer, size_t begin, size_t end)
        {
            if (this->contents_buffer) {
                return this->contents_buffer->create(peer, begin, end);
            }
            DS3_WRONGFUNC_RETVAL(NULL);
        }

    size_t begin() { return 0; }
    size_t end() { return this->size(); }

    virtual int resize(size_t sznew) /**< resize the content, return 0 on success, < 0 on error */
        {
            if (this->contents_buffer) {
                return this->contents_buffer->resize(sznew);
            }
            //DS3_WRONGFUNC_RETVAL(-1);
            if (sznew != 0) {
                return -1;
            }
            return 0;
        }
    virtual uint8_t & at(size_t i);
    uint8_t & operator [](size_t i) { return at(i); }

    /** @brief the total size of this content */
    virtual ssize_t size(void) const
        {
            if (this->contents_buffer) {
                return this->contents_buffer->size();
            }
            //DS3_WRONGFUNC_RETVAL(-1);
            return 0; //to_nbs(NULL, 0);
        }

    /**
     * @brief the size of a sub-block at position pos (including header+content)
     * @return < 0 on error(no enough data)
     */
    virtual ssize_t block_size_at (size_t pos)
        {
            if (this->contents_buffer) {
                return this->contents_buffer->block_size_at(pos);
            }
            DS3_WRONGFUNC_RETVAL(-1);
        }

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
     * insert content from peer.
     * Note: (end_peer - begin_peer) == size of the content to be moved.
     */
    virtual ssize_t insert (size_t pos_self, ds3_packet_buffer_t *peer, size_t begin_peer, size_t end_peer);

    /**
     * @brief copy content from peer
     *
     * @param pos_self : [in] the insert position(self)
     * @param peer : [in,out] the buffer to be copied by this function
     * @param begin_peer : [in] the start position of the content (peer)
     * @param end_peer : [in] the end position of the content (peer)
     *
     * @return the size of data copied on success; < 0 on error
     *
     * copy content from peer.
     * Note: (end_peer - begin_peer) == size of the content to be moved.
     */
    virtual ssize_t copy (size_t pos_self, ds3_packet_buffer_t *peer, size_t begin_peer, size_t end_peer);

    /**
     * @brief convert the packet to network byte sequence and save it to nbsbuf, including the packet header
     * @param nbsbuf : the buffer to be filled, in network byte sequence
     * @param szbuf : the size requested to be filled
     *
     * @return the size of data copied to buffer, >0 on success, < 0 on error
     */
    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf)
        {
            if (this->contents_buffer) {
                return this->contents_buffer->to_nbs(nbsbuf, szbuf);
            }
            DS3_WRONGFUNC_RETVAL(-1);
        }

    /**
     * @brief read the buffer in network byte sequence and save it to structure, including the packet header
     * @param nbsbuf : the buffer to be read, in network byte sequence
     * @param szbuf : the size of the buffer
     *
     * @return the size of data processed, >0 on success, < 0 on error
     */
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf)
        {
            //if (this->contents_buffer) {
            //    return this->contents_buffer->from_nbs(nbsbuf, szbuf);
            //}
            // we don't want to create the content from here,
            // because if we do here, we need contents_buffer be set (with data or null data) before this routine,
            // it's more better to ask the user parse the nbsbuf first and then use copy()/insert() to set the buffer.
            DS3_WRONGFUNC_RETVAL(-1);
        }

     /** @brief get the packet content, only for derived class */
    virtual ds3_packet_buffer_t * get_buffer (void) { return this->contents_buffer; }

protected:
    /**
     * @brief insert content to peer
     *
     * @param pos_peer : [in] the insert position at the peer content class
     * @param peer : [in,out] the buffer to be filled by this function
     * @param begin_self : [in] the start position of the content (self)
     * @param end_self : [in] the end position of the content (self)
     *
     * @return the peer pointer, or a new created class if peer==NULL on success; NULL on error
     *
     * insert content to peer.
     */
    virtual ds3_packet_buffer_t * insert_to (size_t pos_peer, ds3_packet_buffer_t *peer, size_t begin_self, size_t end_self)
        {
            if (this->contents_buffer) {
                return this->contents_buffer->insert_to(pos_peer, peer, begin_self, end_self);
            }
            DS3_WRONGFUNC_RETVAL(NULL);
        }


    /**
     * @brief copy content to peer
     *
     * @param pos_peer : [in] the insert position at the peer content class
     * @param peer : [in,out] the buffer to be filled by this function
     * @param begin_self : [in] the start position of the content (self)
     * @param end_self : [in] the end position of the content (self)
     *
     * @return the peer pointer, or a new created class if peer==NULL on success; NULL on error
     *
     * copy content to peer.
     */
    virtual ds3_packet_buffer_t * copy_to (size_t pos_peer, ds3_packet_buffer_t *peer, size_t begin_self, size_t end_self)
        {
            if (this->contents_buffer) {
                return this->contents_buffer->copy_to(pos_peer, peer, begin_self, end_self);
            }
            DS3_WRONGFUNC_RETVAL(NULL);
        }

private:
    ds3_packet_buffer_t *contents_buffer; /**< the content of child */
};

inline uint8_t &
ds3_packet_buffer_t::at(size_t i)
{
    if (this->contents_buffer) {
        return this->contents_buffer->at(i);
    }
    DS3_WRONGFUNC_EXECEPTION();
}

/**
 * in a derived class, the accepted peer is type of either the same class
 * or base(with the same type of class pointer contents_buffer) class.
 */
#define DS3_PKTCNT_IMPLEMENT_CHILD_COPY(ds3_real_type, pos_self, arg_peer, begin_peer, end_peer) \
    assert (NULL != (arg_peer)); \
    ds3_real_type *peer = dynamic_cast<ds3_real_type *>(arg_peer); \
    if (NULL == peer) { \
        if (NULL != (arg_peer)->get_buffer()) { \
            /* it's a base class, and it stored the content from other ns2 content */ \
            peer = dynamic_cast<ds3_real_type *>((arg_peer)->get_buffer()); \
        } \
    } \
    if (NULL == peer) { \
        return -1; \
    } \
    size_t szorig = this->size(); \
    ds3_packet_buffer_t *new_content = peer->copy_to((pos_self), this, (begin_peer), (end_peer)); \
    if (NULL == new_content) { \
        return -1; \
    } \
    assert (this == new_content); \
    size_t sznew = this->size(); \
    assert (sznew >= szorig); \
    assert (sznew - szorig <= ((end_peer) - (begin_peer))); \
    assert ((pos_self) + ((end_peer) - (begin_peer)) <= sznew); \
    if (sznew > szorig) { \
        return sznew - (pos_self); \
    } else { \
        return ((end_peer) - (begin_peer)); \
    }

#define DS3_PKTCNT_IMPLEMENT_CHILD_INSERT(ds3_real_type, pos_self, arg_peer, begin_peer, end_peer) \
    assert (NULL != (arg_peer)); \
    ds3_real_type *peer = dynamic_cast<ds3_real_type *>(arg_peer); \
    if (NULL == peer) { \
        if (NULL != (arg_peer)->get_buffer()) { \
            peer = dynamic_cast<ds3_real_type *>((arg_peer)->get_buffer()); \
        } \
    } \
    if (NULL == peer) { \
        return -1; \
    } \
    size_t szorig = this->size(); \
    ds3_packet_buffer_t *new_content = peer->insert_to((pos_self), this, (begin_peer), (end_peer)); \
    if (NULL == new_content) { \
        return -1; \
    } \
    assert (this == new_content); \
    size_t sznew = this->size(); \
    assert ((sznew - szorig) <= ((end_peer) - (begin_peer))); \
    return (sznew - szorig);

#define DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS_MINI(ds3_real_type) \
  public: \
    virtual ds3_packet_buffer_t * create(void) { return new ds3_real_type(); } \
    virtual ds3_packet_buffer_t * create(ds3_packet_buffer_t * peer, size_t begin, size_t end) { return new ds3_real_type(peer, begin, end); } \
    ds3_real_type(ds3_packet_buffer_t *peer, size_t begin, size_t end); \
    virtual ~ds3_real_type()

/** declare the common memeber functions: size(), block_size_at(), copy_to(), insert_to() etc. */
#define DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS(ds3_real_type) \
  public: \
    virtual ssize_t copy (size_t pos_self, ds3_packet_buffer_t *arg_peer, size_t begin_peer, size_t end_peer) { \
        DS3_PKTCNT_IMPLEMENT_CHILD_COPY(ds3_real_type, pos_self, arg_peer, begin_peer, end_peer); \
    } \
    virtual ssize_t insert (size_t pos_self, ds3_packet_buffer_t *arg_peer, size_t begin_peer, size_t end_peer) { \
        DS3_PKTCNT_IMPLEMENT_CHILD_INSERT(ds3_real_type, pos_self, arg_peer, begin_peer, end_peer); \
    } \
    virtual int resize(size_t sznew); \
    virtual ssize_t size(void) const; \
    virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf); \
    virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf); \
    virtual ds3_packet_buffer_t * get_buffer (void) { /* this function only valid for base class! let it fail here. */ DS3_WRONGFUNC_RETVAL(NULL); } \
  protected: \
    virtual ds3_packet_buffer_t * copy_to (size_t pos_peer, ds3_packet_buffer_t *peer, size_t begin_self, size_t end_self); \
    virtual ds3_packet_buffer_t * insert_to (size_t pos_peer, ds3_packet_buffer_t *peer, size_t begin_self, size_t end_self); \
    DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS_MINI(ds3_real_type)

/**
 * @brief the packet content class for network byte sequence buffer
 */
class ds3_packet_buffer_nbs_t : public ds3_packet_buffer_t {
protected:
    std::vector<uint8_t> buffer; /**< the content buffer */
public:
    ds3_packet_buffer_nbs_t() {}

    ssize_t append (std::vector<uint8_t>::iterator &begin1, std::vector<uint8_t>::iterator &end1);
    ssize_t append (uint8_t *buf, size_t sz);
    int append_to (std::vector<uint8_t> & buffer1);

#if CCFDEBUG
    virtual void dump (void);
#endif

    virtual uint8_t & at(size_t i);
    //virtual ssize_t block_size_at (size_t pos); // this class may be used as a parent pointer to its children, so we may call child's block_size_at()
    DS3_PKTCNT_DECLARE_MEMBER_FUNCTIONS(ds3_packet_buffer_nbs_t);
};

inline ds3_packet_buffer_nbs_t::~ds3_packet_buffer_nbs_t() {}

inline int ds3_packet_buffer_nbs_t::resize(size_t sznew) { this->buffer.resize(sznew); return 0; }
inline uint8_t & ds3_packet_buffer_nbs_t::at(size_t i) { return this->buffer[i]; }

/* the real packet is stored in peer which is created by this micro, for ds3_packet_buffer_t::insert_to() and copy_to() */
#define DS3_DYNCST_CHKRET_CONTENT_POINTER(ds3_real_type, arg_peer) \
    if (NULL == arg_peer) { \
        /* create a new buf, and copy itself from [begin_self, end_self], return the new buf */ \
        ds3_packet_buffer_t * newpkt = this->create (this, begin_self, end_self); \
        return newpkt; \
    } \
    ds3_real_type *peer = dynamic_cast<ds3_real_type *>(arg_peer); \
    if (NULL == peer) { \
        assert (0); \
        return NULL; \
    } \
    if ((ssize_t)pos_peer > peer->size()) { \
        return NULL; \
    } \
    if ((ssize_t)begin_self >= this->size()) { \
        /* do nothing */ \
        return arg_peer; \
    } \
    if ((ssize_t)end_self > this->size()) { \
        end_self = this->size(); \
    }

#if CCFDEBUG

#ifndef REQUIRE
#define REQUIRE(a) if (! (a)) { std::cerr << "FAIL :< " << #a << " @ " << __func__ << "()" << std::endl; assert(a); return -1; } else { std::cerr << "Passed :) " << #a << " @ " << __func__ << "()" << std::endl; }
#endif

int test_ccfhdr (void);
int test_pktcnt (void);
#endif

#endif // _DS3PKGCNT_H
