//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

#include <LinearRotatingMobilityBase.h>

LinearRotatingMobilityBase::LinearRotatingMobilityBase()
{
    targetOrientation = EulerAngles::IDENTITY;
}

void LinearRotatingMobilityBase::initializeOrientation()
{
    MobilityBase::initializePosition();
    if (!stationary) {
        setTargetOrientation();
        EV_INFO << "current target orientation = " << targetOrientation << ", next change = " << nextChange << endl;
    }
    lastUpdate = simTime();
    scheduleUpdate();
}

void LinearRotatingMobilityBase::rotate()
{
    simtime_t now = simTime();
    if (now == nextChange) {
        lastOrientation = targetOrientation;
        EV_INFO << "reached current target orientation = " << lastOrientation << endl;
        setTargetOrientation();
        EV_INFO << "new target orientation = " << targetOrientation << ", next change = " << nextChange << endl;
    }
    else if (now > lastUpdate) {
        ASSERT(nextChange == -1 || now < nextChange);
        double delta = (simTime() - lastUpdate).dbl() / (nextChange - lastUpdate).dbl();
        lastOrientation = slerp(lastOrientation,targetOrientation,delta);
    }
}

EulerAngles LinearRotatingMobilityBase::slerp(EulerAngles from, EulerAngles to, double delta)
{
    return from + (to - from) * delta;
}
