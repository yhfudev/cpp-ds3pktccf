/**
 * @file    unittest.cc
 * @brief   unittest for DOCSIS CCF
 * @author  Yunhui Fu (yhfudev@gmail.com)
 * @version 1.0
 * @date    2014-06-12
 * @copyright Yunhui Fu (2014)
 */

// https://github.com/philsquared/Catch.git
#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"

#include "testccf.h"
#include "ds3ccfns2.h"

/*****************************************************************************/
TEST_CASE( "Test ccfpack the DOCSIS CCF module", "[ccfpack]" ) {
#if 1
    REQUIRE (0 == test_pktclass());
    REQUIRE (0 == test_machdr());
    REQUIRE (0 == test_ccfhdr());
    REQUIRE (0 == test_pktcnt());
    REQUIRE (0 == test_pack());
    REQUIRE (0 == test_ns2ccf());

#else
    ds3hdr_ccf_t ccfhdr, ccfhdr2, *ph;
    uint8_t buffer[16];

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

    REQUIRE (0 != memcmp (&ccfhdr, &ccfhdr2, sizeof(ccfhdr)));
#endif // 1
}

/*
SCENARIO( "vectors can be sized and resized", "[vector]" ) {

    GIVEN( "A vector with some items" ) {
        std::vector<int> v( 5 );

        REQUIRE( v.size() == 5 );
        REQUIRE( v.capacity() >= 5 );

        WHEN( "the size is increased" ) {
            v.resize( 10 );

            THEN( "the size and capacity change" ) {
                REQUIRE( v.size() == 10 );
                REQUIRE( v.capacity() >= 10 );
            }
        }
        WHEN( "the size is reduced" ) {
            v.resize( 0 );

            THEN( "the size changes but not capacity" ) {
                REQUIRE( v.size() == 0 );
                REQUIRE( v.capacity() >= 5 );
            }
        }
        WHEN( "more capacity is reserved" ) {
            v.reserve( 10 );

            THEN( "the capacity changes but not the size" ) {
                REQUIRE( v.size() == 5 );
                REQUIRE( v.capacity() >= 10 );
            }
        }
        WHEN( "less capacity is reserved" ) {
            v.reserve( 0 );

            THEN( "neither size nor capacity are changed" ) {
                REQUIRE( v.size() == 5 );
                REQUIRE( v.capacity() >= 5 );
            }
        }
    }
}
*/
