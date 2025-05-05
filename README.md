# Multithreaded Exfiltration Detection

An expansion of the exfil module designed by [Reservior Labs](https://github.com/reservoirlabs/bro-scripts/tree/master/exfil-detection-framework), these improved Zeek (formerly Bro) scripts are capable of detecting exfil that leverages multithreading. By aggregating the numerous data streams created by multithreading, exfiltration attempts that previously evaded network detection through many small data streams will now be noticed by Zeek.


## Detection Logic
To understand the basic logic of the main script, check out the [original exfil module README](https://github.com/reservoirlabs/bro-scripts/blob/master/exfil-detection-framework/README.md).

The original exfil module assumed exfiltration occurs over a single, large TCP connection, but exfiltration can occur over many smaller connections via multithreading. This repo's scripts detect the latter scenario by aggregating the byte counts of multiple connections to determine if exfiltration is occurring over many different bytestreams. If multiple outbound data streams with the same source IP, destination IP, and destination port appear in quick succession, the data streams their byte counts are aggregated and treated as a possible exfiltration attempt. If the aggregated byte count surpasses a given byte threshold, an alert is written to the Zeek notice log. There are two main variables that can be tuned to fit detection needs: `thread_check_interval` and `file_thresh`. The `thread_check_interval` defines a period of time to allow other connections to populate  that incidicate multithreaded exfil. The `file_thresh` defines the minimum number of bytes that must be exfiltrated before a notice is written.

## Illustrative Diagram Example:
In this example, 15 MB of data is being exfiltrated over 5 unique data streams that were created because the task was split into 5 threads.
### Multithreaded Exfil Evades Traditional Detection Logic
```   |
      |
      |               
      |xxxxxxxxxxxxxxxxxxxxxxxx 6 MB byte exfil threshold         
      |                                                    * - Data stream from thread 1: 3 MB             
bytes |  * %  #   ^   $                                    % - Data stream from thread 2: 3 MB             
      |  / /  /   /   /                                    # - Data stream from thread 3: 3 MB        
      | / /  /   /   /                                     ^ - Data stream from thread 4: 3 MB
      |/_/__/___/___/_________                             $ - Data stream from thread 5: 3 MB
                  time            
```
Even though the total number of exfiltrated bytes has exceeded the threshold, because each thread consituted its own data stream, none of them individually reach the threshold byte number and no alerts are raised.

### Detecting Multithreaded Exfil by Aggregation
```   |        /
      |       / #
      |      /         
      |xxxxx/xxxxxxxxxxxxxxxxx 6 MB byte exfil threshold         
      |    / %                                             * - Data stream from thread 1: 3 MB
bytes |   /                                                % - Data stream from thread 2: 3 MB
      |  /                                                 # - Data stream from thread 3: 3 MB
      | / *                                               
      |/______________________                             
                  time            
```
Using the Zeek scripts in this repo, the total number of bytes from each of the five threads (three pictured in the diagram) is aggregated and a notice is raised because the byte threshold is crossed.

## Script Explanations
1. **main.zeek** - The primary script that drives the Exfil Framework.
2. **app-exfil-conn.zeek** - The script that attaches the Exfil Framework to connections. You will want to edit the redefs exported by this script to choose which connections get monitored for file uploads. **Note:** Start small. If this script is attached to a lot of connections, it may negatively impact the amount of traffic your Zeek sensor can process.
3. **threaded_exfil.zeek** - Adds events that are necessary for aggregating threads.
4. **__load__.zeek** - Loads all the Exfil Framework scripts. You will not need to edit this file.


## Dependencies
* [JA3](https://github.com/salesforce/ja3) - The exfiltration script refers to the popular JA3 Zeek script, so [ja3.zeek](https://github.com/salesforce/ja3/blob/master/zeek/ja3.zeek) will be required.

## Credits
* [Manju Lalwani](https://www.linkedin.com/in/manjulalwani/) - Research & Project Lead
* [Caleb Yu](https://www.linkedin.com/in/caleb-yu/) - Zeek script programmer and tester
* [Reservior Labs](https://www.reservoir.com/) - Exfil framework baseline
* Salesforce threat detection team
