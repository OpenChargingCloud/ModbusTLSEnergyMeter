#!/bin/bash

git submodule foreach git pull
git pull
dotnet build NornCLI.sln
