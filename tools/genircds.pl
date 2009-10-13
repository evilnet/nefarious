#!/usr/bin/perl
use strict;
#
# genirds.pl - 
#
# Generate testnet ircd instances.
#
# Instructions:
# Create a base.conf in the lib directory, then run this tool. it
# will create 9 ircd sub-directories, each with an ircd.conf in
# it based on taking your base.conf and replacing every occurance
# of __x__ with the counter. 
#
# In your base config, set up your "General" and "Port" blocks using
# __x__ as a placeholder. For example: 
#
#  General {
#           name = "server__x__.mytestnet.net";
#           description = "Testnet server number __x__!";
#           numeric = __x__;
#  };
#  Port {
#           port = 600__x__;
#                server = no;
#            };
#  };
#  Port {
#       port = 440__x__;
#       server = yes;
#  };
# [...rest of the ircd.conf]
#
# You can run each ircd using the -d flag which causes nefarious
# to look in a different directory for its config file.
#  ./ircd -d ircd2/ -h ircd2
#
# WARNING: this script will OVERWRITE any files named ircd.conf
# in numbered ircd subdirectories where you run it. Backup your
# stuff before you use it!
#
# Enjoy!
# -Rubin 

my $start = 1;
my $end = 9;
my $base = "base.conf";

if( -f $base ) {
    my $text = '';
    {
        local( $/, *FH ) ;
        open( FH, $base ) or die "unable to open $base: $!\n";
        $text = <FH>;
        close(FH);
    }

    for(my $i = $start; $i <= $end; $i++) {
        my $path = "ircd".$i;
        my $conf = $text;
        $conf =~ s/__x__/$i/g;
        if(! -d "$path") {
            `mkdir '$path'`;
        }
        open( FW, '>', "$path/ircd.conf") or die("Unable to write to $path/ircd.conf: $!");
        print FW $conf;
        close(FW);
    }
} 
else {
    die("No base.conf in the current directory. Please read the comments for instructions!\n");
}
