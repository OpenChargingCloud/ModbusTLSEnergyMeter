#!/bin/bash

cd libs
cd UsersAPI;             versionHash_UsersAPI=$(git rev-list --max-count=1 HEAD);                cd ..
cd OpenChargingCloudAPI; versionHash_OpenChargingCloudAPI=$(git rev-list --max-count=1 HEAD);    cd ..
#cd ChargeITMobilityAPI;  versionHash_ChargeITMobilityAPI=$(git rev-list --max-count=1 HEAD);     cd ..
#cd ChargeITMobilityAPI;  versionHash_ChargeITMobilityEMPAPI=$(git rev-list --max-count=1 HEAD);  cd ..
cd ..

cd OCPPTests
dotnet run --no-build --no-restore $versionHash_UsersAPI $versionHash_OpenChargingCloudAPI
