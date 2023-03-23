import frrtest


class TestFlag(frrtest.TestMultiOut):
    program = "./test_peer_attr"


# List of tests can be generated by executing:
# $> ./test_peer_attr 2>&1 | sed -n 's/\\/\\\\/g; s/\S\+ \[test\] \(.\+\)/TestFlag.okfail(\x27\1\x27)/pg'
#
TestFlag.okfail("peer\\advertisement-interval")
TestFlag.okfail("peer\\capability dynamic")
TestFlag.okfail("peer\\capability extended-nexthop")
# TestFlag.okfail('peer\\capability extended-nexthop')
TestFlag.okfail("peer\\description")
TestFlag.okfail("peer\\disable-connected-check")
TestFlag.okfail("peer\\dont-capability-negotiate")
TestFlag.okfail("peer\\enforce-first-as")
TestFlag.okfail("peer\\local-as")
TestFlag.okfail("peer\\local-as 1 no-prepend")
TestFlag.okfail("peer\\local-as 1 no-prepend replace-as")
TestFlag.okfail("peer\\override-capability")
TestFlag.okfail("peer\\passive")
TestFlag.okfail("peer\\password")
TestFlag.okfail("peer\\shutdown")
TestFlag.okfail("peer\\strict-capability-match")
TestFlag.okfail("peer\\timers")
TestFlag.okfail("peer\\timers connect")
TestFlag.okfail("peer\\update-source")
TestFlag.okfail("peer\\update-source")
TestFlag.okfail("peer\\ipv4-unicast\\addpath")
TestFlag.okfail("peer\\ipv4-multicast\\addpath")
TestFlag.okfail("peer\\ipv6-unicast\\addpath")
TestFlag.okfail("peer\\ipv6-multicast\\addpath")
TestFlag.okfail("peer\\ipv4-unicast\\allowas-in")
TestFlag.okfail("peer\\ipv4-multicast\\allowas-in")
TestFlag.okfail("peer\\ipv6-unicast\\allowas-in")
TestFlag.okfail("peer\\ipv6-multicast\\allowas-in")
TestFlag.okfail("peer\\ipv4-unicast\\allowas-in origin")
TestFlag.okfail("peer\\ipv4-multicast\\allowas-in origin")
TestFlag.okfail("peer\\ipv6-unicast\\allowas-in origin")
TestFlag.okfail("peer\\ipv6-multicast\\allowas-in origin")
TestFlag.okfail("peer\\ipv4-unicast\\as-override")
TestFlag.okfail("peer\\ipv4-multicast\\as-override")
TestFlag.okfail("peer\\ipv6-unicast\\as-override")
TestFlag.okfail("peer\\ipv6-multicast\\as-override")
TestFlag.okfail("peer\\ipv4-unicast\\attribute-unchanged as-path")
TestFlag.okfail("peer\\ipv4-multicast\\attribute-unchanged as-path")
TestFlag.okfail("peer\\ipv6-unicast\\attribute-unchanged as-path")
TestFlag.okfail("peer\\ipv6-multicast\\attribute-unchanged as-path")
TestFlag.okfail("peer\\ipv4-unicast\\attribute-unchanged next-hop")
TestFlag.okfail("peer\\ipv4-multicast\\attribute-unchanged next-hop")
TestFlag.okfail("peer\\ipv6-unicast\\attribute-unchanged next-hop")
TestFlag.okfail("peer\\ipv6-multicast\\attribute-unchanged next-hop")
TestFlag.okfail("peer\\ipv4-unicast\\attribute-unchanged med")
TestFlag.okfail("peer\\ipv4-multicast\\attribute-unchanged med")
TestFlag.okfail("peer\\ipv6-unicast\\attribute-unchanged med")
TestFlag.okfail("peer\\ipv6-multicast\\attribute-unchanged med")
TestFlag.okfail("peer\\ipv4-unicast\\attribute-unchanged as-path next-hop")
TestFlag.okfail("peer\\ipv4-multicast\\attribute-unchanged as-path next-hop")
TestFlag.okfail("peer\\ipv6-unicast\\attribute-unchanged as-path next-hop")
TestFlag.okfail("peer\\ipv6-multicast\\attribute-unchanged as-path next-hop")
TestFlag.okfail("peer\\ipv4-unicast\\attribute-unchanged as-path med")
TestFlag.okfail("peer\\ipv4-multicast\\attribute-unchanged as-path med")
TestFlag.okfail("peer\\ipv6-unicast\\attribute-unchanged as-path med")
TestFlag.okfail("peer\\ipv6-multicast\\attribute-unchanged as-path med")
TestFlag.okfail("peer\\ipv4-unicast\\attribute-unchanged as-path next-hop med")
TestFlag.okfail("peer\\ipv4-multicast\\attribute-unchanged as-path next-hop med")
TestFlag.okfail("peer\\ipv6-unicast\\attribute-unchanged as-path next-hop med")
TestFlag.okfail("peer\\ipv6-multicast\\attribute-unchanged as-path next-hop med")
TestFlag.okfail("peer\\ipv4-unicast\\capability orf prefix-list send")
TestFlag.okfail("peer\\ipv4-multicast\\capability orf prefix-list send")
TestFlag.okfail("peer\\ipv6-unicast\\capability orf prefix-list send")
TestFlag.okfail("peer\\ipv6-multicast\\capability orf prefix-list send")
TestFlag.okfail("peer\\ipv4-unicast\\capability orf prefix-list receive")
TestFlag.okfail("peer\\ipv4-multicast\\capability orf prefix-list receive")
TestFlag.okfail("peer\\ipv6-unicast\\capability orf prefix-list receive")
TestFlag.okfail("peer\\ipv6-multicast\\capability orf prefix-list receive")
TestFlag.okfail("peer\\ipv4-unicast\\capability orf prefix-list both")
TestFlag.okfail("peer\\ipv4-multicast\\capability orf prefix-list both")
TestFlag.okfail("peer\\ipv6-unicast\\capability orf prefix-list both")
TestFlag.okfail("peer\\ipv6-multicast\\capability orf prefix-list both")
TestFlag.okfail("peer\\ipv4-unicast\\default-originate")
TestFlag.okfail("peer\\ipv4-multicast\\default-originate")
TestFlag.okfail("peer\\ipv6-unicast\\default-originate")
TestFlag.okfail("peer\\ipv6-multicast\\default-originate")
TestFlag.okfail("peer\\ipv4-unicast\\default-originate route-map")
TestFlag.okfail("peer\\ipv4-multicast\\default-originate route-map")
TestFlag.okfail("peer\\ipv6-unicast\\default-originate route-map")
TestFlag.okfail("peer\\ipv6-multicast\\default-originate route-map")
TestFlag.okfail("peer\\ipv4-unicast\\distribute-list")
TestFlag.okfail("peer\\ipv4-multicast\\distribute-list")
TestFlag.okfail("peer\\ipv6-unicast\\distribute-list")
TestFlag.okfail("peer\\ipv6-multicast\\distribute-list")
TestFlag.okfail("peer\\ipv4-unicast\\distribute-list")
TestFlag.okfail("peer\\ipv4-multicast\\distribute-list")
TestFlag.okfail("peer\\ipv6-unicast\\distribute-list")
TestFlag.okfail("peer\\ipv6-multicast\\distribute-list")
TestFlag.okfail("peer\\ipv4-unicast\\filter-list")
TestFlag.okfail("peer\\ipv4-multicast\\filter-list")
TestFlag.okfail("peer\\ipv6-unicast\\filter-list")
TestFlag.okfail("peer\\ipv6-multicast\\filter-list")
TestFlag.okfail("peer\\ipv4-unicast\\filter-list")
TestFlag.okfail("peer\\ipv4-multicast\\filter-list")
TestFlag.okfail("peer\\ipv6-unicast\\filter-list")
TestFlag.okfail("peer\\ipv6-multicast\\filter-list")
TestFlag.okfail("peer\\ipv4-unicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv4-multicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv6-unicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv6-multicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv4-unicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv4-multicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv6-unicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv6-multicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv4-unicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv4-multicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv6-unicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv6-multicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv4-unicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv4-multicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv6-unicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv6-multicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv4-unicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv4-multicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv6-unicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv6-multicast\\maximum-prefix")
TestFlag.okfail("peer\\ipv4-unicast\\next-hop-self")
TestFlag.okfail("peer\\ipv4-multicast\\next-hop-self")
TestFlag.okfail("peer\\ipv6-unicast\\next-hop-self")
TestFlag.okfail("peer\\ipv6-multicast\\next-hop-self")
TestFlag.okfail("peer\\ipv4-unicast\\next-hop-self force")
TestFlag.okfail("peer\\ipv4-multicast\\next-hop-self force")
TestFlag.okfail("peer\\ipv6-unicast\\next-hop-self force")
TestFlag.okfail("peer\\ipv6-multicast\\next-hop-self force")
TestFlag.okfail("peer\\ipv4-unicast\\prefix-list")
TestFlag.okfail("peer\\ipv4-multicast\\prefix-list")
TestFlag.okfail("peer\\ipv6-unicast\\prefix-list")
TestFlag.okfail("peer\\ipv6-multicast\\prefix-list")
TestFlag.okfail("peer\\ipv4-unicast\\prefix-list")
TestFlag.okfail("peer\\ipv4-multicast\\prefix-list")
TestFlag.okfail("peer\\ipv6-unicast\\prefix-list")
TestFlag.okfail("peer\\ipv6-multicast\\prefix-list")
TestFlag.okfail("peer\\ipv4-unicast\\remove-private-AS")
TestFlag.okfail("peer\\ipv4-multicast\\remove-private-AS")
TestFlag.okfail("peer\\ipv6-unicast\\remove-private-AS")
TestFlag.okfail("peer\\ipv6-multicast\\remove-private-AS")
TestFlag.okfail("peer\\ipv4-unicast\\remove-private-AS all")
TestFlag.okfail("peer\\ipv4-multicast\\remove-private-AS all")
TestFlag.okfail("peer\\ipv6-unicast\\remove-private-AS all")
TestFlag.okfail("peer\\ipv6-multicast\\remove-private-AS all")
TestFlag.okfail("peer\\ipv4-unicast\\remove-private-AS replace-AS")
TestFlag.okfail("peer\\ipv4-multicast\\remove-private-AS replace-AS")
TestFlag.okfail("peer\\ipv6-unicast\\remove-private-AS replace-AS")
TestFlag.okfail("peer\\ipv6-multicast\\remove-private-AS replace-AS")
TestFlag.okfail("peer\\ipv4-unicast\\remove-private-AS all replace-AS")
TestFlag.okfail("peer\\ipv4-multicast\\remove-private-AS all replace-AS")
TestFlag.okfail("peer\\ipv6-unicast\\remove-private-AS all replace-AS")
TestFlag.okfail("peer\\ipv6-multicast\\remove-private-AS all replace-AS")
TestFlag.okfail("peer\\ipv4-unicast\\route-map")
TestFlag.okfail("peer\\ipv4-multicast\\route-map")
TestFlag.okfail("peer\\ipv6-unicast\\route-map")
TestFlag.okfail("peer\\ipv6-multicast\\route-map")
TestFlag.okfail("peer\\ipv4-unicast\\route-map")
TestFlag.okfail("peer\\ipv4-multicast\\route-map")
TestFlag.okfail("peer\\ipv6-unicast\\route-map")
TestFlag.okfail("peer\\ipv6-multicast\\route-map")
TestFlag.okfail("peer\\ipv4-unicast\\route-reflector-client")
TestFlag.okfail("peer\\ipv4-multicast\\route-reflector-client")
TestFlag.okfail("peer\\ipv6-unicast\\route-reflector-client")
TestFlag.okfail("peer\\ipv6-multicast\\route-reflector-client")
TestFlag.okfail("peer\\ipv4-unicast\\route-server-client")
TestFlag.okfail("peer\\ipv4-multicast\\route-server-client")
TestFlag.okfail("peer\\ipv6-unicast\\route-server-client")
TestFlag.okfail("peer\\ipv6-multicast\\route-server-client")
TestFlag.okfail("peer\\ipv4-unicast\\send-community")
TestFlag.okfail("peer\\ipv4-multicast\\send-community")
TestFlag.okfail("peer\\ipv6-unicast\\send-community")
TestFlag.okfail("peer\\ipv6-multicast\\send-community")
TestFlag.okfail("peer\\ipv4-unicast\\send-community extended")
TestFlag.okfail("peer\\ipv4-multicast\\send-community extended")
TestFlag.okfail("peer\\ipv6-unicast\\send-community extended")
TestFlag.okfail("peer\\ipv6-multicast\\send-community extended")
TestFlag.okfail("peer\\ipv4-unicast\\send-community large")
TestFlag.okfail("peer\\ipv4-multicast\\send-community large")
TestFlag.okfail("peer\\ipv6-unicast\\send-community large")
TestFlag.okfail("peer\\ipv6-multicast\\send-community large")
TestFlag.okfail("peer\\ipv4-unicast\\soft-reconfiguration inbound")
TestFlag.okfail("peer\\ipv4-multicast\\soft-reconfiguration inbound")
TestFlag.okfail("peer\\ipv6-unicast\\soft-reconfiguration inbound")
TestFlag.okfail("peer\\ipv6-multicast\\soft-reconfiguration inbound")
TestFlag.okfail("peer\\ipv4-unicast\\unsuppress-map")
TestFlag.okfail("peer\\ipv4-multicast\\unsuppress-map")
TestFlag.okfail("peer\\ipv6-unicast\\unsuppress-map")
TestFlag.okfail("peer\\ipv6-multicast\\unsuppress-map")
TestFlag.okfail("peer\\ipv4-unicast\\weight")
TestFlag.okfail("peer\\ipv4-multicast\\weight")
TestFlag.okfail("peer\\ipv6-unicast\\weight")
TestFlag.okfail("peer\\ipv6-multicast\\weight")
TestFlag.okfail("peer\\ipv4-vpn\\accept-own")
TestFlag.okfail("peer\\ipv6-vpn\\accept-own")
