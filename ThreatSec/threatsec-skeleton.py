#!/usr/local/bin/python3

# Course: CS 461 ThreatSec MP
# Author: Adam Bates

import argparse
import csv
from enum import Enum
from functools import reduce
import os
import pdb
import sys

# Enumeration of system calls to map them to
#   specific integer values.
# One way to retreieve a system call's ID is
#   as follows: SYSCALL_IDS["open"].value
# System calls encountered in the log
#   that do not appear in the enumeration
#   should be mapped to SYSCALL_ID.unknown.
SYSCALL_IDS = Enum('syscall_ids', ["accept","access","bind",
                                   "chmod","clone","close",
                                   "connect","execve","fstat",
                                   "ftruncate","listen","mmap2",
                                   "open","read","recv",
                                   "recvfrom","recvmsg","send",
                                   "sendmsg","sendto","stat",
                                   "truncate","unlink","waitpid",
                                   "write","writev","unknown"])

# Interface and required command line arguments for program
parser = argparse.ArgumentParser(description='CS 461 ThreatSec MP.')
parser.add_argument('-d', '--database', type=str,
                    help='path to log file/directory for creating database (i.e., training data)')
parser.add_argument('-t', '--test', type=str,
                    help='path to log file for testing the database (i.e., test data)')
parser.add_argument('-s', '--seqlength', type=int,
                    help='sequence length (window size) used for system calls')

# Provides a 'cleaned' version of the process name to use in your analysis.
#   The log files we're using have this annoying habit of assigning multiple process names
#   to the same executable by instance number, e.g., "mozStorage #1", "mozStorage #2."
#   Treating these as unique programs reduces the number of observations we have per program
#   and will increase the error rate. This function just lobs off the number.
def clean_process_name(process_name):
    return process_name.split(" #")[0]

# We have started the log parsing function for you to make sure that we're
#   all being consistent in how we interpret the log fields.
#   Do not edit the loop logic for extracting log fields,
#   cleaning the process name, or setting pid to tid.
def parse_log(log_file):

    # Note: this code assumes log_file is a file (not a dir).
    #   you will need to wrap or edit this function to support directories.
    with open(log_file,"r") as log:
        logreader = csv.reader(log, delimiter=",", skipinitialspace=True)
        next(logreader) # skip headers
        for event in logreader:

            # Retrieve relevant log fields
            try:
                (ret_val, ret_time, call_time, process_name, pid, tid, syscall) = event[:7] 
            except:
                # There are some badly-formed lines in some of our log data
                #   due to, e.g., incorrectly escaped syscall arguments.
                #   For our purposes we're just going to drop these and continue
                continue

            # Cleaning up process names so that processes running the same executable
            # are grouped together in the database, see helper function.
            process_name = clean_process_name(process_name)
            
            # We are going to use the thread identifier as the process identifier.
            #   As a reminder, pid==tid in a single threaded process.
            #   Just setting pid equal to tid here to avoid any confusion.
            tid = int(tid)
            pid = tid
            
            if syscall in SYSCALL_IDS.__members__:
                syscall_id = SYSCALL_IDS[syscall].value
            else:
                syscall_id = SYSCALL_IDS.unknown.value

                
    return -1                

if __name__ == "__main__":

    args = parser.parse_args()
    

    if not (os.path.isfile(args.database) or os.path.isdir(args.database)):
        print("Error: %s is not a valid file path" % (args.database), file=sys.stderr)
        sys.exit(1)
        
    if not os.path.isfile(args.test):
        print("Error: %s is not a valid file path" % (args.test), file=sys.stderr)
        sys.exit(2)
        



