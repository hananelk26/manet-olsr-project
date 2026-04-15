build_lib(
  LIBNAME olsr
  SOURCE_FILES
    helper/olsr-helper.cc
    model/olsr-header.cc
    model/olsr-routing-protocol.cc
    model/olsr-state.cc
    # --- New Security Files ---
    model/olsr-defense-strategy.cc
    model/olsr-defense-cooperative.cc
    model/olsr-defense-gcop.cc

  HEADER_FILES
    helper/olsr-helper.h
    model/olsr-header.h
    model/olsr-repositories.h
    model/olsr-routing-protocol.h
    model/olsr-state.h
    # --- New Security Headers ---
    model/olsr-defense-strategy.h
    model/olsr-defense-cooperative.h
    model/olsr-defense-gcop.h

  LIBRARIES_TO_LINK 
    ${libinternet}
    ${libwifi}            # Required for PHY/MAC access (Sniffer)
    ${libtraffic-control} # Required for QueueDisc monitoring

  TEST_SOURCES
    test/regression-test-suite.cc
    test/bug780-test.cc
    test/hello-regression-test.cc
    test/olsr-header-test-suite.cc
    test/olsr-routing-protocol-test-suite.cc
    test/tc-regression-test.cc
)