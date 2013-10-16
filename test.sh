#!/bin/bash

for i in *txt
do
    echo $i
    ./client -U -f $i xinu06:$1 > junk
    echo `diff $i rcvd`
done
for i in *jpg
do
    echo $i
    ./client -U -f $i xinu06:$1 > junk
    echo `diff $i rcvd`
done
