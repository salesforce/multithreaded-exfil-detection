# Copyright (c) 2022, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause

module Exfil;

## This function determines if exfiltration has occurred via multithreading
event Exfil::thread_check(c: connection, s: Settings, b: count) {
    local c_key = (fmt("%s->%s:%s", c$id$orig_h, c$id$resp_h, c$id$resp_p));

    if (c_key in thread_collection)
    {
        # If there is only a single connection with a particular source IP, destination IP, and destination port over 5 seconds
        # threading is not happening, so the connection can be removed.
        if (thread_collection[c_key]$thread_cnt == 1)
        {
            delete thread_collection[c_key];
        }
        
        # Once the byte count given by the function is equal to the byte count given by the last time the function was run
        # it is safe to assume all threads have been completed.  If the byte count is high enough, raise a notice.
        else if (b == thread_collection[c_key]$timed_byte_cnt)
        {
            if ((thread_collection[c_key]$thread_cnt >= s$unique_thread_thresh) && (thread_collection[c_key]$total_byte_cnt > s$file_thresh))
            {
                NOTICE([
                    $id=c$id,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h,
                    $p=c$id$resp_p,
                    $note=Exfil::File_Transfer,
                    $msg=fmt("A total of %d bytes have gone from %s to %s:%s over %d unique streams", (thread_collection[c_key]$total_byte_cnt), (c$id$orig_h), (c$id$resp_h), (c$id$resp_p), (thread_collection[c_key]$thread_cnt)),
                    $sub="This is multithreaded exfiltration"]);
                delete thread_collection[c_key];
                return;
                
            }
            # If the byte count is not high enough, delete the connection from the table
            else
            {
                delete thread_collection[c_key];
                return;
            }
        }
        else
        {
            thread_collection[c_key]$timed_byte_cnt = (thread_collection[c_key]$total_byte_cnt);            
            return;
        }
    }
    return;

}


# This function adds a new connection to the threads table
function add_conn_to_threads (c: connection, s: Settings, new_thread: bool) {

    # It gathers information in the same way as it would for any connection
    local session = tracked_sessions[c$uid];
    # get latest information from c$id
    lookup_connection(c$id);
    # set last_byte_cnt to current byte count
    session$last_byte_cnt = c$orig$size;

    # The table tracked_sessions uses relies on the source IP, destination IP, and destination port as a key
    local new_key = (fmt("%s->%s:%s", c$id$orig_h, c$id$resp_h, c$id$resp_p));
    local add_entry = T;

    for (x, y in tracked_sessions)
    {
        for (key in thread_collection)
        {
            if (key == new_key)
            {
                add_entry = F;
                local new_bytes = (y$last_byte_cnt - y$orig_byte_cnt);
                if (new_thread == T)
                {
                    thread_collection[new_key]$thread_cnt += 1;
                    new_thread = F;
                }
                thread_collection[new_key]$total_byte_cnt += new_bytes;
                y$orig_byte_cnt = y$last_byte_cnt;
                break;
            }
        }
        if (add_entry == T)
        {
            thread_collection[new_key] = [$thread_cnt=1, $total_byte_cnt=y$last_byte_cnt, $timed_byte_cnt=0];
            y$orig_byte_cnt = y$last_byte_cnt;
            new_thread = F;
        }
    }
}

