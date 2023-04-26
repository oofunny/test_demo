#!/bin/bash
source ~/.bashrc
shopt -s expand_aliases

echo Cleaning up...
sca -b annotatedPrimaryComponent_NoFalseNegatives -clean
rm *.log
rm *.fpr

echo Translating...
sca -b annotatedPrimaryComponent_NoFalseNegatives -debug -logfile annotatedPrimaryComponent_NoFalseNegatives.translation.java.log -cp "libraries/thirdPartyComponent.jar:libraries/FortifyAnnotations-SOURCE.jar" -source 1.5 annotatedPrimaryComponent_NoFalseNegatives/**/*.java

echo Scanning...
sca -b annotatedPrimaryComponent_NoFalseNegatives -debug -logfile annotatedComponent_NoFalseNegatives.scan.log -scan -f annotatedPrimaryComponent_NoFalseNegatives.fpr
