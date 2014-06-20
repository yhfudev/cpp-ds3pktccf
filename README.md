DS3PKTCCF {#mainpage}
=========

# DOCSIS 3.1 Continuous Concatenation and Fragmentation module

DS3PKTCCF is an C++ library for the [DOCSIS 3.1](http://www.cablelabs.com/specs/specification-search/?cat=docsis) Continuous Concatenation and Fragmentation(CCF).
The library supply the entire set of API methods including:

* **pack** - pack all of the MAC packet into CCF segments for CM sending to CMTS.
* **unpack** - rearrange the CCF segments by the sequence number in the segment header, and reassembly it so that it can extract all of the MAC packets at CMTS.

## Install
There are a few different ways you can install DS3PKTCCF:

* Use auto-tools: `./configure && make`
* Copy the source code from directory src to your project.
   
## Getting Started
* Install DS3PKTCCF
* **copy files** - copy the file `ds3pktccf.cc,ds3pktccf.h`.
* derive your own classes from: `ds3packet_t, ds3_ccf_pack_t, ds3_ccf_unpack_t`

## Examples

    /* classes for NS2 */
    class ds3packet_ns2_t : public ds3packet_t {
    public:
        virtual ~ds3packet_ns2_t() { }
        virtual ssize_t to_nbs (uint8_t *nbsbuf, size_t szbuf);
        virtual ssize_t from_nbs (uint8_t *nbsbuf, size_t szbuf);
        virtual ssize_t hdr_to_nbs (uint8_t *nbsbuf, size_t szbuf);

    private:
        // ...
    };

    class ds3ns2_ccf_pack_t : public ds3_ccf_pack_t {
    public:
    protected:
        virtual int start_sndpkt_timer (double abs_time, ds3event_t evt, ds3packet_t * p, size_t channel_id);
        virtual double current_time (void);
    };

    class ds3ns2_ccf_unpack_t : public ds3_ccf_unpack_t {
    public:
    protected:
        virtual int signify_packet (std::vector<uint8_t> & macbuffer);
        virtual int signify_piggyback (int sc, size_t request);
    };

    int
    test_pack (void)
    {
        int i = 0;
        int j = 0;
        double next_gt_time = 0.0;
        ds3ns2_ccf_pack_t pak;
        ds3ns2_ccf_unpack_t unpak;
        std::vector<ds3_grant_t> mygrants;
        ds3_grant_t gt;
        ds3packet_ns2_t * pkt2 = NULL;
        uint8_t pktcontent[5];
        memset (pktcontent, 0xBF, sizeof(pktcontent));

        next_gt_time = 0.0;
        my_set_time (next_gt_time);

        pak.set_pbmultiplier(5);
        unpak.set_pbmultiplier(5);
        REQUIRE (5 == pak.get_pbmultiplier());
        REQUIRE (5 == unpak.get_pbmultiplier());

        next_gt_time = 1.0;
        gt.set_size(8+7+2*2); // CCF header(8) + data(7) + NUM_PKT*sizeof(machdr)
        gt.set_channel_id(1);
        gt.set_time(next_gt_time);
        mygrants.push_back (gt);

        next_gt_time = 2.0;
        gt.set_size(8+11+2*2);
        gt.set_channel_id(1);
        gt.set_time(next_gt_time);
        mygrants.push_back (gt);

        next_gt_time = 3.0;
        gt.set_size(8+7+1*2);
        gt.set_channel_id(1);
        gt.set_time(next_gt_time);
        mygrants.push_back (gt);

        next_gt_time = 4.0;
        gt.set_size(8+7+1*2);
        gt.set_channel_id(1);
        gt.set_time(next_gt_time);
        mygrants.push_back (gt);

        // we add 5 packet (size=5)
        for (i = 0; i < NUM_PKT; i ++) {
            pkt2 = new ds3packet_ns2_t ();
            assert (NULL != pkt2);
            pkt2->set_content (pktcontent, 5);
            pak.process_packet(pkt2);
            std::cout << "channel packet # = " << get_channel_packet_length() << std::endl;
        }

        pak.add_grants (mygrants, 355);
        std::cout << "channel packet # = " << get_channel_packet_length() << std::endl;
        REQUIRE ( 3 == get_channel_packet_length() );

        next_gt_time = 1.0;
        my_set_time (next_gt_time);

        // ``transfer the segments
        // since we append the new assemblied packet to the same global vector,
        // so we need to get the original length of the queue.
        ds3packet_t *pkt;
        j = 0;
        for (i = get_channel_packet_length() + 1; i > 0; i --, j ++) {
            pkt = get_channel_packet(j);
            unpak.process_packet (pkt);
            set_channel_packet (j, NULL); // because the CCF packet were deleted by the process_packet()
        }
        std::cout << "channel packet # = " << get_channel_packet_length() << std::endl;
        REQUIRE ( 3 + NUM_PKT == get_channel_packet_length() );

        j = 0;
        for (i = get_channel_packet_length() + 1; i > 0; i --, j ++) {
            pkt = get_channel_packet(j);
            set_channel_packet (j, NULL);
            if (NULL != pkt) {
                delete pkt;
            }
        }
        return 0;
    }
    
