#!/bin/bash
mvn install:install-file -Dfile=libGoogleAnalyticsV2.jar -DgroupId=com.google.android.analytics -DartifactId=analytics -Dversion=V2 -Dpackaging=jar
