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

ds3_packet_buffer_t *
ds3_packet_buffer_ns2_t::insert_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self)
{
    DS3_DYNCST_CHKRET_CONTENT_POINTER(ds3_packet_buffer_ns2_t, arg_peer);
    // TODO: add the content between [begin_self, end_self) to peer
    assert (0);
    return arg_peer;
}

ds3_packet_buffer_t *
ds3_packet_buffer_ns2_t::copy_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self)
{
    DS3_DYNCST_CHKRET_CONTENT_POINTER(ds3_packet_buffer_ns2_t, arg_peer);
    // TODO: copy the content between [begin_self, end_self) to peer
    assert (0);
    return arg_peer;
}

ds3_packet_buffer_ns2_t::ds3_packet_buffer_ns2_t(ds3_packet_buffer_t *arg_peer, size_t begin, size_t end)
{
    ds3_packet_buffer_ns2_t * peer = dynamic_cast<ds3_packet_buffer_ns2_t *> (arg_peer);
    assert (NULL != peer);
    assert (0); // TODO
}

int
ds3_packet_buffer_ns2_t::resize(size_t sznew)
{
    assert (0); // TODO
    return -1;
}

ssize_t
ds3_packet_buffer_ns2_t::size(void)
{
    assert (0); // TODO
    return -1;
}

uint8_t &
ds3_packet_buffer_ns2_t::at(size_t i)
{
    static uint8_t t = -1;
    DS3_WRONGFUNC_RETVAL(t);
}

ssize_t
ds3_packet_buffer_ns2_t::block_size_at (size_t pos)
{
    // size of sub-block (including header+content)
    assert (0); // TODO
    return -1;
}

ssize_t
ds3_packet_buffer_ns2_t::to_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    assert (0); // TODO
    return -1;
}

ssize_t
ds3_packet_buffer_ns2_t::from_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    assert (0); // TODO
    return -1;
}

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
#endif

#if CCFDEBUG
void
ds3packet_ns2mac_t::dump (void)
{
    this->dump_content ();
}
#endif

ssize_t
ds3packet_ns2mac_t::to_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    ssize_t szret = -1;
    assert (0); // TODO:
    return szret;
}

ssize_t
ds3packet_ns2mac_t::from_nbs (uint8_t *nbsbuf, size_t szbuf)
{
    ssize_t szret = -1;
    assert (0); // TODO:
    return szret;
}

ssize_t
ds3packet_ns2mac_t::from_nbs (ds3_packet_buffer_t *peer, size_t pos_peer)
{
    ssize_t szret = -1;
    assert (0); // TODO:
    return szret;
}

/**
 * This function only support ns2 Packet buffer!
 */
ds3_packet_buffer_t *
ds3packet_ns2mac_t::insert_to (size_t pos_peer, ds3_packet_buffer_t *arg_peer, size_t begin_self, size_t end_self)
{
    DS3_DYNCST_CHKRET_DS3PKT_BUFFER(ds3_packet_buffer_ns2_t, arg_peer);

    assert (NULL != peer);
    if (begin_self >= end_self) {
        return arg_peer;
    }

    assert (0); // TODO:
    return NULL;
}
