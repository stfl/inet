//
// Copyright (C) 2008 Irene Ruengeler
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//

package inet.examples.sctp.mysctp;

import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import ned.DatarateChannel;


network multihomed
{
    parameters:
        double testTimeout @unit(s) = default(0s);
        bool testing = default(false);

    submodules:
        sctp_client: StandardHost {
            parameters:
                forwarding = false;
                networkLayer.configurator.networkConfiguratorModule = "";
                @display("p=61,142;i=device/laptop");

                // @statistic[rcvdPk_hist](title="packets received hist"; source=rcvdPk; record=histogram; interpolationmode=none);
                @statistic[sentPk_hist](title="packets sent hist"; source=sentPk; record="histogram(packetBytes)"; interpolationmode=none);
                @statistic[echoedPk](title="packets echoed"; source=echoedPk; record=count,"sum(packetBytes)","vector(packetBytes)"; interpolationmode=none);
            gates:
                pppg[2];
        }
        sctp_server: StandardHost {
            parameters:
                forwarding = false;
                networkLayer.configurator.networkConfiguratorModule = "";
                @display("p=426,135;i=device/server2");
            gates:
                pppg[2];

        }
        router1: Router {
            parameters:
                networkLayer.configurator.networkConfiguratorModule = "";
                @display("p=188,77;i=abstract/router");
            gates:
                pppg[4];
        }
        router2: Router {
            parameters:
                networkLayer.configurator.networkConfiguratorModule = "";
                @display("p=323,75;i=abstract/router");
            gates:
                pppg[4];
        }
    connections:	
        sctp_client.pppg[0] <--> LTEPath <--> router1.pppg[0];
        sctp_client.pppg[1] <--> LTEPath_slow <--> router1.pppg[1];
        router1.pppg[2] <--> NormalPath_slow <--> router2.pppg[0];
        router1.pppg[3] <--> NormalPath <--> router2.pppg[1];
        router2.pppg[2] <--> FastPath <--> sctp_server.pppg[0];
        router2.pppg[3] <--> FastPath <--> sctp_server.pppg[1];
}

channel LTEPath extends DatarateChannel
{
    parameters:
        delay = 20ms;
        datarate = 40Mbps;
        //per = 0.005;   // packet error rate
}

channel LTEPath_slow extends DatarateChannel
{
    parameters:
        delay = 20ms;
        datarate = 20Mbps;
        //per = 0.005;   // packet error rate
}

channel NormalPath extends DatarateChannel
{
   parameters:
      delay = 5ms;
      datarate = 4Mbps;

}

channel NormalPath_slow extends DatarateChannel
{
   parameters:
      delay = 5ms;
      datarate = 2Mbps;
}

channel FastPath extends DatarateChannel
{
    parameters:
        delay = 2ms;
        datarate = 1Gbps;
}

