#!/bin/bash

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=YES
export AFL_SKIP_CPUFREQ=YES

./start.sh $*
