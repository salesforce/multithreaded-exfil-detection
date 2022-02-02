# Contributed by Bob Rotsted @ Reservoir Labs
#
# Small Business Innovation Research (SBIR) Data Rights.
#
# These SBIR data are furnished with SBIR rights under Contract
# No. DE-SC0004400 and DE-SC0006343. For a period of 4 years
# (expiring August, 2018), unless extended in accordance with
# FAR 27.409(h), subject to Section 8 of the SBA SBIR Policy
# Directive of August 6, 2012, after acceptance of all items to
# be delivered under this contract, theGovernment will use these
# data for Government purposes only, and theyshall not be
# disclosed outside the Government (including disclosure for
# procurement purposes) during such period without permission of
# the Contractor, except that, subject to the foregoing use and
# disclosure prohibitions, these data may be disclosed for use
# by support Contractors. After the protection period, the
# Government has a paid-up license to use, and to authorize
# others to use on its behalf, these data for Government
# purposes, but is relieved of all disclosure prohibitions and
# assumes no liability for unauthorized use of these data by
# third parties. This notice shall be affixed to any
# reproductions of these data, in whole or in part.
#
## Modified to include JA3 by John Althouse
#
## Modified for detecting multithreaded exfiltration by Manju Lalwani and Caleb Yu
#
##! This is the base module of the Exfil Framework. The Exfil Framework is a library for the detection of outbound bytestreams.

module Exfil;

export {

    redef enum Log::ID += { LOG, DEBUG };

    ## Define the default Notice::Type for Exfil events
    redef enum Notice::Type += {
        File_Transfer,
    };

    type Info: record {

        ## Timestamp
        ts: time     &log;
        ## UID
        uid: string &log;
        ## The connection record
        id: conn_id &log;
        ## Transport Protocol
    	proto: transport_proto &log;
    	## Service
    	service: set[string] &log &optional;
    	## Host name if cleartext
    	host: string &log &optional;
    	## SSL Server Name
    	server_name: string &log &optional;
    	## Subject of the X.509 certificate
    	subject: string &log &optional;
    	## JA3 SSL Client Fingerprint
    	ja3: string &log &optional;
    	## SSL Certificate Validation Status
    	validation_status: string &log &optional;
        ## How many bytes were sent?
        orig_bytes: count &log;
        ## what happened?
        note: Notice::Type &log;

    };

    type DebugInfo: record {

        ts: time     &log;
        id: conn_id &log;
        uid: string &log;
        byte_rate: double &log;
        reported: bool &log;
        byte_count: count &log;

    };

    ## A public data structure for defining thresholds and reporting Settings
    type Settings: record {

        ## How often should we poll this connection. A smaller value leads to more accurate detection and file size estimation.
        checkup_interval: interval &default=1sec;
        ## How soon should we check for another connection with the same source IP, destination IP, and destination port?
        thread_checkup_interval: interval &default=5sec;
        ## What must the byte rate be to flag it as a transfer. Note: We have found that 2000/bytes per second is a good threshold. If you wish to change
        ## the checkup interval or byte_rate_thresh, you may want to increase the byte_rate_thresh in 2000/bytes per second increments.
        byte_rate_thresh: count &default=2000;
        ## How many bytes constitute a file transfer.
        file_thresh: count &default=65536;
        ## How many unique connections should be seen to consider the possibility of multithreading.
        unique_thread_thresh: count &default=20;
        ## Deliver this to the notice framework?
        notice: bool &default=F;
        ## Define notice type for this transfer
        note: Notice::Type &default=Exfil::File_Transfer;

    };

    ## This turns on the 'debug' log, shows byte rates by connection
    global debug: bool = F &redef;

    ## The logging event for the Exfil::Log
    global log_exfil: event(rec: Info);

    ## The logging event for the Exfil::Log
    global log_debug: event(rec: DebugInfo);

    ## Event associated with addition to state table
    global watching_connection: event(c: connection);

    ## Event associated with removal from state table
    global forgetting_connection: event(c: connection);

    ## Event associated with the beginning of a heuristically detected transfer
    global heuristic_transfer_begin: event(c: connection);

    ## Event associated with the end of a heuristically detected transfer
    global heuristic_transfer_end: event(c: connection);

    ## Event assoicated with a flow surpassing the byte threshold defined in file_thresh of Settings
    global transfer_above_file_thresh: event(c: connection);

    ## Event assoicated with a flow below the byte threshold defined in file_thresh of Settings
    global transfer_below_file_thresh: event(c: connection);

    ## Public interface for Exfil Framework
    global watch_connection: function(c: connection, s: Settings);
    
    ## Checks to see if a set of threads has exfiltrated a file
    global thread_check: event(c: connection, s: Settings, b: count);

    ## Aggregates multiple connections that are likely threads of a single process
    global add_conn_to_threads: function(c: connection, s: Settings, new_thread: bool);

}

    ## A private data structure for tracking byte counts and reporting state
    type connection_stats: record {
        src_ip: addr;
        src_p: port;
        dst_ip: addr;
        dst_p: port;
        orig_byte_cnt: count &default=0;
        last_byte_cnt: count &default=0;
        reported: bool &default=F;

    };

    type thread_aggregation_stats: record {
        thread_cnt: count &default=0;
        total_byte_cnt: count &default=0;
        timed_byte_cnt: count &default=0;
    };

    ## This is the data structure that holds our tracked sessions
    type sessions: table[string] of connection_stats &create_expire=1day;
    
    ## This is the data strucutre that holds our aggregated threads
    type threading_stats: table[string] of thread_aggregation_stats &create_expire=1hr;

    ## This holds all connections tracked by the framework
    global tracked_sessions: sessions;
    
    ## This holds all the aggregated threadeds tracked by the framework
    global thread_collection: threading_stats;

event zeek_init() &priority=5 {

    Log::create_stream(Exfil::LOG, [$columns=Info, $ev=log_exfil]);
    Log::create_stream(Exfil::DEBUG, [$columns=DebugInfo, $ev=log_debug]);

}

function alert( c: connection, byte_cnt: count, n: Notice::Type, notice: bool) {

    local rec = Exfil::Info($ts=network_time(), $uid=c$uid, $id=c$id, $proto=(get_port_transport_proto(c$id$orig_p)), $service=c$service, $orig_bytes=byte_cnt, $note=n);
       if (c?$ssl) {
		if (c$ssl?$subject) {
        		rec$subject = c$ssl$subject;
        	}
		rec$server_name = c$ssl$server_name;
        	rec$ja3 = c$ssl$ja3;
        	if (c$ssl?$validation_status) {
			rec$validation_status = c$ssl$validation_status;
        	}
	}
    if (c?$http) rec$host = c$http$host;
    
    Log::write(Exfil::LOG, rec);
    
    if (notice) {
   # if ( $orig_bytes > 262144000 )
   # if ( $orig_bytes != 18446744073709551615 ) {

        NOTICE([$note=n,
                $id=c$id,
                $msg=fmt("Large file upload detected from %s to %s. This file is approximately %s bytes.", c$id$orig_h, c$id$resp_h, byte_cnt),
                $sub=c$ssl$subject]);
    }

}

event Exfil::regular_check(c: connection, s: Settings) {
    # Does this connection still exist? If it doesn't remove it from tracking and don't schedule a checkup
    local byte_cnt: count;
    
    if (! connection_exists(c$id)) {
        if (c$uid in tracked_sessions) {
            if ( tracked_sessions[c$uid]$reported ) {
                byte_cnt = (tracked_sessions[c$uid]$last_byte_cnt - tracked_sessions[c$uid]$orig_byte_cnt);
        		event Exfil::heuristic_transfer_end(c);
                if ( byte_cnt >= s$file_thresh) {
                    # Fire an event that signals that this event has ended
                    event Exfil::transfer_above_file_thresh(c);
                    alert(c,byte_cnt,s$note,s$notice);
                   # If byte_cnt < notification threshold but the burst is over fire a transfer_below_file_thresh event
                } else {
                    event Exfil::transfer_below_file_thresh(c);
                }
            }
            event Exfil::forgetting_connection(c);
            delete tracked_sessions[c$uid];
        }
        return;
    }

    local new_thread: bool = F;
    # Has this connection been tracked yet? If not track it, set counters to default vals and return
    if (c$uid !in tracked_sessions) {

        event Exfil::watching_connection(c);
        tracked_sessions[c$uid] = [$last_byte_cnt = c$orig$size, $src_ip=c$id$orig_h, $src_p=c$id$orig_p, $dst_ip=c$id$resp_h, $dst_p=c$id$resp_p];
        # Assume the new connection is a single thread of many
	new_thread = T;
        add_conn_to_threads(c, s, new_thread);
        local conn_key = (fmt("%s->%s:%s", c$id$orig_h, c$id$resp_h, c$id$resp_p));
	# Schedule another check and check for more connections with the same source and destination IP 5 seconds later.
        schedule s$checkup_interval { Exfil::regular_check(c, s) };
        schedule s$thread_checkup_interval { Exfil::thread_check(c, s, thread_collection[conn_key]$total_byte_cnt) };
        return;

    }
    
    local session = tracked_sessions[c$uid];
    # get latest information from c$id
    lookup_connection(c$id);

    # byte_rate = (current byte count) - (byte count at last poll) / (polling interval)
    local byte_rate: double = 
        ((c$orig$size - session$last_byte_cnt) + 0.0 / interval_to_double(s$checkup_interval));

    # set last_byte_cnt to current byte count
    session$last_byte_cnt = c$orig$size;

    # if the current byte_rate is greater than our byte rate threshold
    if (byte_rate > s$byte_rate_thresh && session$reported == F) { 

        # Flag this connection for reporting
        session$reported = T;
        session$orig_byte_cnt = c$orig$size;

        event Exfil::heuristic_transfer_begin(c);

    }

    # determine how much data has been seen
    byte_cnt = (c$orig$size - session$orig_byte_cnt);

	# If debugging is turned on, write the debug log
	if (debug) { 
    	local debug_rec: Exfil::DebugInfo = [$ts=network_time(), $id=c$id, $uid=c$uid, $byte_rate=byte_rate, 
                                                $reported=session$reported, $byte_count=byte_cnt];
    	Log::write(Exfil::DEBUG, debug_rec);
	}

    # if the current byte_rate has returned from the burst, notice, log, etc.
    if ( session$reported && byte_rate < s$byte_rate_thresh ) {

        event Exfil::heuristic_transfer_end(c);
        if ( byte_cnt >= s$file_thresh) {
        
            # Fire an event that signals that this event has ended
            event Exfil::transfer_above_file_thresh(c);
            alert(c,byte_cnt,s$note,s$notice);

        # If byte_cnt < notification threshold but the burst is over fire a transfer_below_file_thresh event
        } else {
            event Exfil::transfer_below_file_thresh(c);
        }

        # Return connection to "unreported" state
        session$reported = F;
   
    }    
    
    
    add_conn_to_threads(c, s, new_thread);
    local new_key = (fmt("%s->%s:%s", c$id$orig_h, c$id$resp_h, c$id$resp_p));

    # Schedule next checkup and a checkup to see if the connection is one of many threads
    schedule s$thread_checkup_interval { Exfil::thread_check(c, s, thread_collection[new_key]$total_byte_cnt) };
    schedule s$checkup_interval { Exfil::regular_check(c, s) };
    #Schedule something new and if there is no additional entry, delete it.
}


## A public interface for attaching connections to the analyzer
function watch_connection (c: connection, s: Settings) {

    schedule s$checkup_interval { Exfil::regular_check(c, s) };

}
