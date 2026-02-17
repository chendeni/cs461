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
parser.add_argument('-o', '--output', type=str,
                    help='csv output file')



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
    syscall_trace = {}
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
            #print(syscall)
            #print(syscall_id)
            
            if(syscall_trace.get((process_name, tid)) == None):
                syscall_trace[(process_name, tid)] = []

            syscall_trace[(process_name, tid)].append(syscall_id)
			
    #print(log_file)
    #print(len(syscall_trace))
    return syscall_trace

def parse_multilog(path):
    multilog_trace = {}
    files = ["cnn_train", "download_train", "game_train","gmail_train","youtube_train"]
    if(os.path.isfile(path)):
        files = [""]

    for i in files:
        log_file = path+i
        trace = parse_log(log_file)
        for j in trace:
            #print(trace[j])
            if(multilog_trace.get(j[0]) == None):
                multilog_trace[j[0]] = []
            multilog_trace[j[0]].append(trace[j])
    
    #total = 0
    #for i in multilog_trace:
    #    print(len(multilog_trace[i]))
    #    total += len(multilog_trace[i])
    #print(total)
    #print(len(multilog_trace))
    return multilog_trace
            
            
def create_database(traces, seqlength):
    databases = {}
    for process in traces:
        database = {}
        for trace in traces[process]:
            #print(process)
            #print(trace)
            
            for i in range(len(trace)):
                sequence = []
                for j in range(seqlength):
                    if(i+j < len(trace)):
                        sequence.append(trace[i+j])
                    else:
                        sequence.append(SYSCALL_IDS.unknown.value)

                if(database.get(tuple(sequence)) == None):
                    database[tuple(sequence)] = 0;

                #print(sequence)
                
        if(databases.get(process) != None):
            print("duplicate process trace")
        databases[process] = database
    #print(databases)
    #count = 0
    #for i in databases:
    #    #print(databases[i])
    #    print(len(databases[i]))
    #    count += len(databases[i])
    #print(count)
    return databases
    
        
def scan_anomalies(databases, test, seqlength):
    #print(databases.get("Chrome_ChildThr"))
    report = []
    for test_process in test:
        #print(test[test_process])
        trace = test[test_process]

        #if(report.get(test_process) != None): 
        #    print("duplicate test process")

        if(databases.get(test_process[0]) == None):
            #print("unknown process")
            report.append((test_process[0], test_process[1], -99, 1.0))
            continue
        
        database = databases[test_process[0]]
        anomaly_count = 0.0
        total_count = 0
        for i in range(len(trace)):
            sequence = []

            for j in range(seqlength):
                if(i+j < len(trace)):
                    sequence.append(trace[i+j])
                else:
                    sequence.append(SYSCALL_IDS.unknown.value)

            if(database.get(tuple(sequence)) == None):
                anomaly_count += 1.0;
            total_count += 1    
        report.append((test_process[0], test_process[1], anomaly_count, anomaly_count/total_count))
    
    report.sort(key=get_process_name)

    #for i in report:
    #    print(i)
    return report

def get_process_name(e):
    return (e[0], e[1])
        


def write_csv(report, filename):
    data = []
    for i in report:
        row = []
        row.append(str(i[0]))
        row.append(str(i[1]))
        row.append(str(int(i[2])))
        row.append(str(int(i[3]*100))+"%")
        #print(row)
        data.append(row)
    
    if(filename != None):
        with open(filename, 'w') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerows(data)
    else:
        for row in data:
            print(row[0]+", "+row[1]+", "+row[2]+", "+row[3])

        
    return
        
    
#            sequence.append(trace[i])
#            if(i+1 < len(trace)):
#                sequence.append(trace[i+1])
#            else:
#                sequence.append(SYSCALL_IDS.unknown.value)
#            if(i+2 < len(trace)):
#                sequence.append(trace[i+2])
#            else:
#                sequence.append(SYSCALL_IDS.unknown.value)
#            if(i+3 < len(trace)):
#                sequence.append(trace[i+3])
#            else:
#                sequence.append(SYSCALL_IDS.unknown.value)




if __name__ == "__main__":

    args = parser.parse_args()

    if not (os.path.isfile(args.database) or os.path.isdir(args.database)):
        print("Error: %s is not a valid file path" % (args.database), file=sys.stderr)
        sys.exit(1)
        
    if not os.path.isfile(args.test):
        print("Error: %s is not a valid file path" % (args.test), file=sys.stderr)
        sys.exit(2)
    
    #print(args)
    #print(args.database)
    
    #if(os.path.isfile(args.database)):
    #    parse_log(args.database)
    #elif(os.path.isdir(args.database)):
    traces = parse_multilog(args.database)

    databases = create_database(traces, args.seqlength)
    test = parse_log(args.test)
	
    report = scan_anomalies(databases, test, args.seqlength)
    #print(args.output)
    #if((args.output != None)):
        #print(args.output)
    write_csv(report, args.output)

    
    
	


