"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )
	
        # Add nodes for domain 1
	d1rm   = self.addHost('d1rm' )
        d1cr2  = self.addHost('d1cr2')
        d1cr4  = self.addHost('d1cr4')
        d1cr5  = self.addHost('d1cr5')
        d1br3  = self.addHost('d1br3')
        d1br6  = self.addHost('d1br6')

        # Add links for domain 1
        self.addLink(d1rm ,d1cr2,port1=0,port2=0)
        self.addLink(d1rm ,d1br3,port1=1,port2=3)
        self.addLink(d1cr2,d1br3,port1=1,port2=4)
        self.addLink(d1cr2,d1cr4,port1=2,port2=0)
        self.addLink(d1cr2,d1cr5,port1=3,port2=0)
        self.addLink(d1cr4,d1br3,port1=1,port2=2)
        self.addLink(d1cr4,d1cr5,port1=3,port2=1)
        self.addLink(d1cr4,d1br6,port1=2,port2=0)
        self.addLink(d1cr5,d1br6,port1=2,port2=1)

        # Add nodes for domain 2
	d2rm   = self.addHost('d2rm' )
	d2cr4  = self.addHost('d2cr4')
	d2br1  = self.addHost('d2br1')
	d2br2  = self.addHost('d2br2')
	d2br3  = self.addHost('d2br3')
	d2br7  = self.addHost('d2br7')
	d2br8  = self.addHost('d2br8')

        # Add links for domain 2
        self.addLink(d2rm ,d2br1,port1=2,port2=4)
        self.addLink(d2rm ,d2br8,port1=3,port2=0)
        self.addLink(d2cr4,d2br1,port1=2,port2=3)
        self.addLink(d2cr4,d2br2,port1=3,port2=3)
        self.addLink(d2cr4,d2br3,port1=4,port2=2)
        self.addLink(d2cr4,d2br8,port1=5,port2=1)
        self.addLink(d2br1,d2br2,port1=2,port2=9)
        self.addLink(d2br3,d2br7,port1=5,port2=2)
        self.addLink(d2br7,d2br8,port1=0,port2=2)

        # Add nodes for domain 3
	d3rm   = self.addHost('d3rm' )
	d3cr4  = self.addHost('d3cr4')
	d3br2  = self.addHost('d3br2')
	d3br3  = self.addHost('d3br3')
	d3br5  = self.addHost('d3br5')
	d3br6  = self.addHost('d3br6')

        # Add links for domain 3
        self.addLink(d3rm ,d3br2,port1=0,port2=1)
        self.addLink(d3rm ,d3cr4,port1=1,port2=0)
        self.addLink(d3br2,d3cr4,port1=2,port2=1)
        self.addLink(d3br2,d3br3,port1=3,port2=1)
        self.addLink(d3br3,d3cr4,port1=2,port2=2)
        self.addLink(d3br3,d3br5,port1=3,port2=1)
        self.addLink(d3br5,d3cr4,port1=2,port2=3)
        self.addLink(d3br5,d3br6,port1=3,port2=2)
        self.addLink(d3br6,d3cr4,port1=1,port2=4)

        # Add nodes for domain 4
	d4rm   = self.addHost('d4rm' )
        d4cr7  = self.addHost('d4cr7')
        d4br2  = self.addHost('d4br2')
        d4br4  = self.addHost('d4br4')
        d4br5  = self.addHost('d4br5')
        d4br6  = self.addHost('d4br6')

        # Add links for domain 4
        self.addLink(d4rm ,d4br2,port1=1,port2=1)
        self.addLink(d4rm ,d4cr7,port1=0,port2=2)
        self.addLink(d4cr7,d4br2,port1=1,port2=0)
        self.addLink(d4cr7,d4br4,port1=0,port2=2)
        self.addLink(d4cr7,d4br6,port1=3,port2=7)
        self.addLink(d4br4,d4br5,port1=5,port2=0)
        self.addLink(d4br5,d4br6,port1=1,port2=4)

        # Add nodes for domain 5
	d5rm   = self.addHost('d5rm' )
        d5cr4  = self.addHost('d5cr4')
        d5cr5  = self.addHost('d5cr5')
        d5cr6  = self.addHost('d5cr6')
        d5cr7  = self.addHost('d5cr7')
        d5br1  = self.addHost('d5br1')
        d5br2  = self.addHost('d5br2')
        d5br8  = self.addHost('d5br8')
        d5br9  = self.addHost('d5br9')

        # Add links for domain 5
        self.addLink(d5rm ,d5br2,port1=2,port2=2)
        self.addLink(d5rm ,d5cr5,port1=4,port2=2)
        self.addLink(d5cr5,d5cr4,port1=3,port2=2)
        self.addLink(d5cr5,d5br2,port1=4,port2=3)
        self.addLink(d5cr5,d5cr6,port1=5,port2=3)
        self.addLink(d5cr4,d5cr7,port1=3,port2=3)
        self.addLink(d5cr4,d5br8,port1=4,port2=3)
        self.addLink(d5cr4,d5cr6,port1=5,port2=2)
        self.addLink(d5cr6,d5cr7,port1=4,port2=4)
        self.addLink(d5cr6,d5br8,port1=5,port2=4)
        self.addLink(d5cr7,d5br1,port1=1,port2=3)
        self.addLink(d5cr7,d5br2,port1=2,port2=4)
        self.addLink(d5cr7,d5br9,port1=5,port2=3)
        self.addLink(d5br2,d5br1,port1=5,port2=2)
        self.addLink(d5br1,d5br9,port1=4,port2=2)
        self.addLink(d5br9,d5br8,port1=4,port2=2)

        # Add nodes for domain 6
	d6rm   = self.addHost('d6rm' )
        d6cr9  = self.addHost('d6cr9')
        d6cr10 = self.addHost('d6cr10')
        d6cr12 = self.addHost('d6cr12')
        d6br11 = self.addHost('d6br11')
        d6br14 = self.addHost('d6br14')

        # Add links for domain 6
        self.addLink(d6rm ,d6br14,port1=2,port2=2)
        self.addLink(d6rm ,d6cr12,port1=3,port2=3)
        self.addLink(d6cr10,d6br14,port1=2,port2=0)
        self.addLink(d6cr10,d6cr9 ,port1=3,port2=3)
        self.addLink(d6cr10,d6cr12,port1=4,port2=4)
        self.addLink(d6cr10,d6br11,port1=5,port2=2)
        self.addLink(d6cr12,d6cr9 ,port1=2,port2=2)
        self.addLink(d6br11,d6br14,port1=3,port2=1)

        # Add links for inter domain path
        self.addLink(d1br6,d2br1,port1=2,port2=5)
        self.addLink(d1br3,d3br2,port1=5,port2=0)
        self.addLink(d2br2,d3br3,port1=2,port2=0)
        self.addLink(d2br3,d3br5,port1=3,port2=0)
        self.addLink(d2br8,d4br4,port1=4,port2=3)
        self.addLink(d2br7,d4br2,port1=3,port2=2)
        self.addLink(d2br3,d5br1,port1=4,port2=0)
        self.addLink(d3br6,d5br2,port1=0,port2=0)
        self.addLink(d4br6,d5br9,port1=5,port2=0)
        self.addLink(d4br5,d6br11,port1=2,port2=4)
        self.addLink(d5br8,d6br14,port1=0,port2=4)


topos = { 'mytopo': ( lambda: MyTopo() ) }
