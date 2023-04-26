#!/bin/bash
source ~/.bashrc
shopt -s expand_aliases

echo Cleaning up...
sca -b annotatedPrimaryComponent_NoFalsePositives -clean
rm *.log
rm *.fpr

echo Translating...
sca -b annotatedPrimaryComponent_NoFalsePositives -debug -logfile annotatedPrimaryComponent_NoFalsePositives.translation.java.log -cp "libraries/thirdPartyComponent.jar:libraries/FortifyAnnotations-SOURCE.jar" -source 1.5 annotatedPrimaryComponent_NoFalsePositives/**/*.java

echo Scanning...
sca -b annotatedPrimaryComponent_NoFalsePositives -debug -logfile annotatedComponent_NoFalsePositives.scan.log -scan -f annotatedPrimaryComponent_NoFalsePositives.fpr
