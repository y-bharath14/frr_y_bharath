#!/usr/bin/env python

#
# test_ospf6_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2016 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_ospf6_topo1.py:

                                                  -----\
  SW1 - Stub Net 1            SW2 - Stub Net 2          \
  fc00:1:1:1::/64             fc00:2:2:2::/64            \
\___________________/      \___________________/          |
          |                          |                    |
          |                          |                    |
          | ::1                      | ::2                |
+---------+---------+      +---------+---------+          |
|        R1         |      |        R2         |          |
|     FRRouting     |      |     FRRouting     |          |
| Rtr-ID: 10.0.0.1  |      | Rtr-ID: 10.0.0.2  |          |
+---------+---------+      +---------+---------+          |
          | ::1                      | ::2                 \
           \______        ___________/                      OSPFv3
                  \      /                               Area 0.0.0.0
                   \    /                                  /
             ~~~~~~~~~~~~~~~~~~                           |
           ~~       SW5        ~~                         |
         ~~       Switch         ~~                       |
           ~~  fc00:A:A:A::/64 ~~                         |
             ~~~~~~~~~~~~~~~~~~                           |
                     |                 /----              |
                     | ::3            | SW3 - Stub Net 3  | 
           +---------+---------+    /-+ fc00:3:3:3::/64   |
           |        R3         |   /  |                  /
           |     FRRouting     +--/    \----            /
           | Rtr-ID: 10.0.0.3  | ::3        ___________/
           +---------+---------+                       \
                     | ::3                              \
                     |                                   \
             ~~~~~~~~~~~~~~~~~~                           |
           ~~       SW6        ~~                         |
         ~~       Switch         ~~                       |
           ~~  fc00:B:B:B::/64 ~~                          \
             ~~~~~~~~~~~~~~~~~~                             OSPFv3
                     |                                   Area 0.0.0.1
                     | ::4                                 /
           +---------+---------+       /----              |
           |        R4         |      | SW4 - Stub Net 4  |
           |     FRRouting     +------+ fc00:4:4:4::/64   |
           | Rtr-ID: 10.0.0.4  | ::4  |                   /
           +-------------------+       \----             /
                                                   -----/
"""

import os
import re
import sys
import pytest
import platform
from time import sleep

from functools import partial

from mininet.topo import Topo

# Save the Current Working Directory to find configuration files later.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
import platform

#####################################################
##
##   Network Topology Definition
##
#####################################################


class NetworkTopo(Topo):
    "OSPFv3 (IPv6) Test Topology 1"

    def build(self, **_opts):
        "Build function"

        tgen = get_topogen(self)

        # Create 4 routers
        for routern in range(1, 5):
            tgen.add_router("r{}".format(routern))

        #
        # Wire up the switches and routers
        # Note that we specify the link names so we match the config files
        #

        # Create a empty network for router 1
        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"], nodeif="r1-stubnet")

        # Create a empty network for router 2
        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["r2"], nodeif="r2-stubnet")

        # Create a empty network for router 3
        switch = tgen.add_switch("s3")
        switch.add_link(tgen.gears["r3"], nodeif="r3-stubnet")

        # Create a empty network for router 4
        switch = tgen.add_switch("s4")
        switch.add_link(tgen.gears["r4"], nodeif="r4-stubnet")

        # Interconnect routers 1, 2, and 3
        switch = tgen.add_switch("s5")
        switch.add_link(tgen.gears["r1"], nodeif="r1-sw5")
        switch.add_link(tgen.gears["r2"], nodeif="r2-sw5")
        switch.add_link(tgen.gears["r3"], nodeif="r3-sw5")

        # Interconnect routers 3 and 4
        switch = tgen.add_switch("s6")
        switch.add_link(tgen.gears["r3"], nodeif="r3-sw6")
        switch.add_link(tgen.gears["r4"], nodeif="r4-sw6")


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(NetworkTopo, mod.__name__)
    tgen.start_topology()

    logger.info("** %s: Setup Topology" % mod.__name__)
    logger.info("******************************************")

    # For debugging after starting net, but before starting FRR,
    # uncomment the next line
    # tgen.mininet_cli()

    router_list = tgen.routers()
    logger.info("Testing with VRF Lite support")
    krel = platform.release()

    # May need to adjust handling of vrf traffic depending on kernel version
    l3mdev_accept = 0
    if (
        topotest.version_cmp(krel, "4.15") >= 0
        and topotest.version_cmp(krel, "4.18") <= 0
    ):
        l3mdev_accept = 1

    if topotest.version_cmp(krel, "5.0") >= 0:
        l3mdev_accept = 1

    logger.info(
        "krel '{0}' setting net.ipv6.tcp_l3mdev_accept={1}".format(krel, l3mdev_accept)
    )

    cmds = [
        "ip link add {0}-cust1 type vrf table 1001",
        "ip link add loop1 type dummy",
        "ip link set {0}-stubnet master {0}-cust1",
    ]

    cmds1 = [
        "ip link set {0}-sw5 master {0}-cust1",
    ]

    cmds2 = [
        "ip link set {0}-sw6 master {0}-cust1",
    ]

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.iteritems():
        # create VRF rx-cust1 and link rx-eth0 to rx-cust1
        for cmd in cmds:
            output = tgen.net[rname].cmd(cmd.format(rname))
        if rname == "r1" or rname == "r2" or rname == "r3":
            for cmd in cmds1:
                output = tgen.net[rname].cmd(cmd.format(rname))
        if rname == "r3" or rname == "r4":
            for cmd in cmds2:
                output = tgen.net[rname].cmd(cmd.format(rname))

        output = tgen.net[rname].cmd("sysctl -n net.ipv4.tcp_l3mdev_accept")
        logger.info(
            "router {0}: existing tcp_l3mdev_accept was {1}".format(rname, output)
        )

        if l3mdev_accept:
            output = tgen.net[rname].cmd(
                "sysctl -w net.ipv4.tcp_l3mdev_accept={}".format(l3mdev_accept)
            )

   
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/ospf6d.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()

    # For debugging after starting FRR daemons, uncomment the next line
    # tgen.mininet_cli()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()

def test_ospf6_converged():

    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # For debugging, uncomment the next line
    # tgen.mininet_cli()

    # Wait for OSPF6 to converge  (All Neighbors in either Full or TwoWay State)
    logger.info("Waiting for OSPF6 convergence")

    # Set up for regex
    pat1 = re.compile("^[0-9]")
    pat2 = re.compile("Full")

    timeout = 60
    while timeout > 0:
        logger.info("Timeout in %s: " % timeout),
        sys.stdout.flush()

        # Look for any node not yet converged
        for router, rnode in tgen.routers().iteritems():
            resStr = rnode.vtysh_cmd("show ipv6 ospf vrf {0}-cust1 neigh".format(router))

            isConverged = False

            for line in resStr.splitlines():
                res1 = pat1.match(line)
                if res1:
                    isConverged = True
                    res2 = pat2.search(line)

                    if res2 == None:
                        isConverged = False
                        break

            if isConverged == False:
                logger.info("Waiting for {}".format(router))
                sys.stdout.flush()
                break

        if isConverged:
            logger.info("Done")
            break
        else:
            sleep(5)
            timeout -= 5

    if timeout == 0:
        # Bail out with error if a router fails to converge
        ospfStatus = rnode.vtysh_cmd("show ipv6 ospf neigh")
        assert False, "OSPFv6 did not converge:\n{}".format(ospfStatus)

    logger.info("OSPFv3 converged.")

    # For debugging, uncomment the next line
    # tgen.mininet_cli()

    # Make sure that all daemons are still running
    if tgen.routers_have_failure():
        assert tgen.errors == "", tgen.errors


def compare_show_ipv6_vrf(rname, expected):
    """
    Calls 'show ipv6 route' for router `rname` and compare the obtained
    result with the expected output.
    """
    tgen = get_topogen()

    # Use the vtysh output, with some masking to make comparison easy
    vrf_name = "{0}-cust1".format(rname)
    current = topotest.ip6_route_zebra(tgen.gears[rname], vrf_name)
    
    # Use just the 'O'spf lines of the output
    linearr = []
    for line in current.splitlines():
        if re.match("^O", line):
            linearr.append(line)

    current = "\n".join(linearr)

    return topotest.difflines(
        topotest.normalize_text(current),
        topotest.normalize_text(expected),
        title1="Current output",
        title2="Expected output",
    )


def test_ospfv3_routingTable():

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # For debugging, uncomment the next line
    # tgen.mininet_cli()
    # Verify OSPFv3 Routing Table
    for router, rnode in tgen.routers().iteritems():
        logger.info('Waiting for router "%s" convergence', router)

        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/show_ipv6_vrf_route.ref".format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_vrf, router, expected)
        result, diff = topotest.run_and_expect(test_func, "", count=120, wait=0.5)
        assert result, "OSPFv3 did not converge on {}:\n{}".format(router, diff)


def test_linux_ipv6_kernel_routingTable():

    dist = platform.dist()

    if dist[1] == "16.04":
        pytest.skip("Kernel not supported for vrf")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Verify Linux Kernel Routing Table
    logger.info("Verifying Linux IPv6 Kernel Routing Table")

    failures = 0

    # Get a list of all current link-local addresses first as they change for
    # each run and we need to translate them
    linklocals = []
    for i in range(1, 5):
        linklocals += tgen.net["r{}".format(i)].get_ipv6_linklocal()

    # Now compare the routing tables (after substituting link-local addresses)

    for i in range(1, 5):
        # Actual output from router
        actual = tgen.gears["r{}".format(i)].run("ip -6 route show vrf r{}-cust1".format(i)).rstrip()
        if "nhid" in actual:
            refTableFile = os.path.join(CWD, "r{}/ip_6_address.nhg.ref".format(i))
        else:
            refTableFile = os.path.join(CWD, "r{}/ip_6_address.ref".format(i))

        if os.path.isfile(refTableFile):
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines())).splitlines(1)

            # Mask out Link-Local mac addresses
            for ll in linklocals:
                actual = actual.replace(ll[1], "fe80::__(%s)__" % ll[0])
            # Mask out protocol name or number
            actual = re.sub(r"[ ]+proto [0-9a-z]+ +", "  proto XXXX ", actual)
            actual = re.sub(r"[ ]+nhid [0-9]+ +", " nhid XXXX ", actual)
            # Remove ff00::/8 routes (seen on some kernels - not from FRR)
            actual = re.sub(r"ff00::/8.*", "", actual)

            # Strip empty lines
            actual = actual.lstrip()
            actual = actual.rstrip()
            actual = re.sub(r"  +", " ", actual)

            filtered_lines = []
            for line in sorted(actual.splitlines()):
                if line.startswith("fe80::/64 ") or line.startswith(
                    "unreachable fe80::/64 "
                ):
                    continue
                if 'anycast' in line:
                    continue
                filtered_lines.append(line)
            actual = "\n".join(filtered_lines).splitlines(1)

            # Print Actual table
            # logger.info("Router r%s table" % i)
            # for line in actual:
            #     logger.info(line.rstrip())

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual OSPFv3 IPv6 routing table",
                title2="expected OSPFv3 IPv6 routing table",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed Linux IPv6 Kernel Routing Table Check:\n%s\n"
                    % (i, diff)
                )
                failures += 1
            else:
                logger.info("r%s ok" % i)

            assert failures == 0, (
                "Linux Kernel IPv6 Routing Table verification failed for router r%s:\n%s"
                % (i, diff)
            )


def test_shutdown_check_stderr():

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        logger.info(
            "SKIPPED final check on StdErr output: Disabled (TOPOTESTS_CHECK_STDERR undefined)\n"
        )
        pytest.skip("Skipping test for Stderr output")

    net = tgen.net

    logger.info("\n\n** Verifying unexpected STDERR output from daemons")
    logger.info("******************************************")

    for i in range(1, 5):
        net["r%s" % i].stopRouter()
        log = net["r%s" % i].getStdErr("ospf6d")
        if log:
            logger.info("\nRouter r%s OSPF6d StdErr Log:\n%s" % (i, log))
        log = net["r%s" % i].getStdErr("zebra")
        if log:
            logger.info("\nRouter r%s Zebra StdErr Log:\n%s" % (i, log))


def test_shutdown_check_memleak():
    "Run the memory leak test and report results."

    if os.environ.get("TOPOTESTS_CHECK_MEMLEAK") is None:
        logger.info(
            "SKIPPED final check on Memory leaks: Disabled (TOPOTESTS_CHECK_MEMLEAK undefined)"
        )
        pytest.skip("Skipping test for memory leaks")

    tgen = get_topogen()

    net = tgen.net

    for i in range(1, 5):
        net["r%s" % i].stopRouter()
        net["r%s" % i].report_memory_leaks(
            os.environ.get("TOPOTESTS_CHECK_MEMLEAK"), os.path.basename(__file__)
        )


if __name__ == "__main__":

    # To suppress tracebacks, either use the following pytest call or
    # add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])

    retval = pytest.main(["-s"])
    sys.exit(retval)
