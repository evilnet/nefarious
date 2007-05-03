#!/usr/bin/perl
# by Core of the AfterNET irc network
#
$sc="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
@c=split("",$sc);srand(time);$s=$c[int(64*rand())].$c[int(64*rand())];
printf("%s\n",crypt($ARGV[0],$s));
