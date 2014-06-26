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
