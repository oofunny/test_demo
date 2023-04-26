#!/bin/bash
source ~/.bashrc
shopt -s expand_aliases

echo Cleaning up...
sca -b originalPrimaryComponent -clean
rm *.log
rm *.fpr

echo Translating...
sca -b originalPrimaryComponent -debug -logfile originalPrimaryComponent.translation.java.log -cp "libraries/thirdPartyComponent.jar:libraries/FortifyAnnotations-SOURCE.jar" -source 1.5 originalPrimaryComponent/**/*.java

echo Scanning...
sca -b originalPrimaryComponent -debug -logfile originalPrimaryComponent.scan.log -scan -f originalPrimaryComponent.fpr
