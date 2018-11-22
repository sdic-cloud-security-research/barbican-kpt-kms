#!/bin/bash

if [ `whoami` != 'root' ]
  then
    echo 'You must be root to execute this.'
    exit
fi